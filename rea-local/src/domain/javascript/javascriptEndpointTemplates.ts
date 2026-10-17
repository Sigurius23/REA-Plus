import * as t from "@babel/types";

import {
  readExactJavaScriptLiteral,
  unwrapJavaScriptExpression,
} from "./javascriptAstValues.js";

/** Stands for one expression's text in a rendered endpoint template. */
export const ENDPOINT_PLACEHOLDER = "{}";

type Piece = { readonly text: string } | { readonly expression: t.Node };

const exactText = (node: t.Node): string | undefined => {
  const literal = readExactJavaScriptLiteral(node);
  return literal.found &&
    (typeof literal.value === "string" || typeof literal.value === "number")
    ? String(literal.value)
    : undefined;
};

/** One operand's pieces: its exact text, its own pieces, or itself. */
const operand = (node: t.Node): readonly Piece[] => {
  const text = exactText(node);
  if (text !== undefined) return [{ text }];
  return pieces(node) ?? [{ expression: node }];
};

const hasText = (parts: readonly Piece[]): boolean =>
  parts.some((part) => "text" in part);

/** Split string-building syntax into text and expressions, or undefined. */
const pieces = (node: t.Node): readonly Piece[] | undefined => {
  node = unwrapJavaScriptExpression(node).node;
  if (t.isTemplateLiteral(node)) {
    const { expressions } = node;
    return node.quasis.flatMap((quasi, index) => {
      const expression = expressions[index];
      return [
        { text: quasi.value.cooked ?? quasi.value.raw },
        ...(expression === undefined ? [] : operand(expression)),
      ];
    });
  }
  if (t.isBinaryExpression(node) && node.operator === "+") {
    const parts = [...operand(node.left), ...operand(node.right)];
    // Only a string operand makes `+` concatenate.
    return hasText(parts) ? parts : undefined;
  }
  if (
    t.isCallExpression(node) &&
    t.isMemberExpression(node.callee) &&
    !node.callee.computed &&
    t.isIdentifier(node.callee.property, { name: "concat" })
  ) {
    const head = operand(node.callee.object);
    if (!hasText(head)) return undefined;
    return [
      ...head,
      ...node.arguments.flatMap((argument) =>
        t.isSpreadElement(argument)
          ? [{ expression: argument }]
          : operand(argument),
      ),
    ];
  }
  return undefined;
};

const render = (parts: readonly Piece[]): string => {
  let rendered = "";
  for (const part of parts) {
    if ("text" in part) rendered += part.text;
    else if (!rendered.endsWith(ENDPOINT_PLACEHOLDER))
      rendered += ENDPOINT_PLACEHOLDER;
  }
  return rendered;
};

/** A path, a URL, or an unknown base followed by a path. */
const ENDPOINT_SHAPE = /^(?:\.{0,2}\/|[A-Za-z][A-Za-z0-9+.-]*:\/\/|\{\}\/)/u;

/**
 * Render a URL built from strings and expressions, such as
 * `` `/threads/${id}/` `` or `"/threads/".concat(id)`, with `{}` for each
 * expression. Only results shaped like a path or URL are returned.
 */
export const endpointTemplate = (node: t.Node): string | undefined => {
  const parts = pieces(node);
  if (parts?.some((part) => "expression" in part) !== true) return undefined;
  const rendered = render(parts);
  // `${base}/${path}?${query}` names nothing.
  return ENDPOINT_SHAPE.test(rendered) &&
    /[\p{L}\p{N}]/u.test(rendered.replaceAll(ENDPOINT_PLACEHOLDER, ""))
    ? rendered
    : undefined;
};

interface Scope {
  readonly node: t.Node;
  readonly function: boolean;
  readonly values: Map<string, string | undefined>;
}

/**
 * Track the path or URL each local variable was last given, in source order,
 * so `let url = `/threads/${id}/`; get(url)` resolves. Values are known only
 * from a declaration or a plain assignment in the current or an enclosing
 * scope; anything else, including parameters, is unknown.
 */
export class EndpointBindings {
  readonly #scopes: Scope[] = [];

  enter(node: t.Node, parent: t.Node | null): void {
    if (t.isFunctionDeclaration(node) && node.id != null)
      this.#declare(node.id.name, undefined, true);
    if (t.isProgram(node) || t.isFunction(node)) {
      this.#push(node, true);
      if (t.isFunction(node))
        for (const param of node.params) this.#declareAll(param, false);
    } else if (
      (t.isBlockStatement(node) && !t.isFunction(parent)) ||
      t.isCatchClause(node) ||
      t.isFor(node)
    ) {
      this.#push(node, false);
      if (t.isCatchClause(node) && node.param != null)
        this.#declareAll(node.param, false);
    }
    if (t.isVariableDeclarator(node)) this.#declarator(node, parent);
    if (t.isAssignmentExpression(node)) this.#assignment(node);
  }

  exit(node: t.Node): void {
    if (this.#scopes.at(-1)?.node === node) this.#scopes.pop();
  }

  /** The path or URL a string, template or tracked variable stands for. */
  resolve(node: t.Node): string | undefined {
    node = unwrapJavaScriptExpression(node).node;
    if (!t.isIdentifier(node)) {
      const text = exactText(node);
      return text !== undefined && ENDPOINT_SHAPE.test(text)
        ? text
        : endpointTemplate(node);
    }
    for (let index = this.#scopes.length - 1; index >= 0; index -= 1) {
      const values = this.#scopes[index]?.values;
      if (values?.has(node.name) === true) return values.get(node.name);
    }
    return undefined;
  }

  #push(node: t.Node, isFunction: boolean): void {
    this.#scopes.push({ node, function: isFunction, values: new Map() });
  }

  #declare(name: string, value: string | undefined, hoisted: boolean): void {
    const scope = hoisted
      ? this.#scopes.findLast((candidate) => candidate.function)
      : this.#scopes.at(-1);
    scope?.values.set(name, value);
  }

  #declareAll(pattern: t.Node, hoisted: boolean): void {
    for (const name of Object.keys(t.getBindingIdentifiers(pattern)))
      this.#declare(name, undefined, hoisted);
  }

  #declarator(node: t.VariableDeclarator, parent: t.Node | null): void {
    const hoisted = t.isVariableDeclaration(parent) && parent.kind === "var";
    if (!t.isIdentifier(node.id) || node.init == null) {
      this.#declareAll(node.id, hoisted);
      return;
    }
    this.#declare(node.id.name, this.resolve(node.init), hoisted);
  }

  #assignment(node: t.AssignmentExpression): void {
    if (!t.isIdentifier(node.left)) return;
    const name = node.left.name;
    const scope = this.#scopes.findLast(({ values }) => values.has(name));
    if (scope === undefined) return;
    // `url += "?page=2"` and `url = `${url}?${query}`` keep the known prefix.
    if (node.operator === "+=" || this.#extends(name, node.right)) return;
    scope.values.set(
      name,
      node.operator === "=" ? this.resolve(node.right) : undefined,
    );
  }

  #extends(name: string, value: t.Node): boolean {
    const first = pieces(value)?.find(
      (part) => !("text" in part) || part.text !== "",
    );
    return (
      first !== undefined &&
      "expression" in first &&
      t.isIdentifier(unwrapJavaScriptExpression(first.expression).node, {
        name,
      })
    );
  }
}
