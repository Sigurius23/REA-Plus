/**
 * C source of a small game-like program in two versions. The newer one
 * changes `update_player` (a constant and a new callee), removes
 * `old_cheat_check`, adds `anti_tamper`, inserts `log_frame` early so every
 * later function moves, and leaves the rest alone.
 */
export const gameSource = (newer: boolean): string => `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { float x, y, vx, vy; int hp, score, frame; } player_t;
static unsigned crc_table[256];
static player_t players[8];

${newer ? `static void log_frame(int frame) { if (frame % 600 == 0) fprintf(stderr, "frame %d\\n", frame); }` : ""}

static void build_crc_table(void) {
  for (unsigned n = 0; n < 256; n++) {
    unsigned c = n;
    for (int k = 0; k < 8; k++) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
    crc_table[n] = c;
  }
}

static unsigned crc32_buf(const unsigned char *buf, size_t len) {
  unsigned c = 0xffffffffu;
  while (len--) c = crc_table[(c ^ *buf++) & 0xff] ^ (c >> 8);
  return c ^ 0xffffffffu;
}

static unsigned adler32_buf(const unsigned char *buf, size_t len) {
  unsigned a = 1, b = 0;
  while (len--) { a = (a + *buf++) % 65521; b = (b + a) % 65521; }
  return (b << 16) | a;
}

__attribute__((noinline)) unsigned checksum_crc(const void *p, size_t n) { return crc32_buf(p, n); }
__attribute__((noinline)) unsigned checksum_adler(const void *p, size_t n) { return adler32_buf(p, n); }

static int parse_level(const char *text) {
  if (strncmp(text, "level=", 6) != 0) { fputs("bad level line\\n", stderr); return -1; }
  return atoi(text + 6);
}

static int load_config(const char *path, int *level) {
  FILE *f = fopen(path, "r");
  char line[128];
  if (!f) { perror("config.ini"); return -1; }
  while (fgets(line, sizeof line, f)) {
    if (line[0] == '#') continue;
    int value = parse_level(line);
    if (value >= 0) *level = value;
  }
  fclose(f);
  return 0;
}

${
  newer
    ? ""
    : `static int old_cheat_check(const player_t *p) {
  if (p->score > 1000000 || p->hp > 9999) { fputs("cheat detected\\n", stderr); return 1; }
  return 0;
}`
}

${
  newer
    ? `static int anti_tamper(const player_t *p, unsigned expected) {
  unsigned sum = checksum_crc(p, sizeof *p) ^ checksum_adler(p, sizeof *p);
  if (sum != expected) { fputs("tamper detected\\n", stderr); exit(3); }
  return 0;
}`
    : ""
}

static void update_player(player_t *p, float dt) {
  p->x += p->vx * dt;
  p->y += p->vy * dt;
  if (p->y < 0) { p->y = 0; p->vy = -p->vy * 0.5f; }
  p->score += ${newer ? "25" : "10"};
  p->frame++;
  ${newer ? "if (anti_tamper(p, 0x5eed)) p->score = 0;" : "if (old_cheat_check(p)) p->score = 0;"}
}

static void damage(player_t *p, int amount) {
  p->hp -= amount;
  if (p->hp <= 0) { printf("player died at frame %d\\n", p->frame); p->hp = 0; }
}

static void render(const player_t *p, int count) {
  for (int i = 0; i < count; i++)
    printf("%d: (%.1f, %.1f) hp=%d score=%d\\n", i, p[i].x, p[i].y, p[i].hp, p[i].score);
}

static int save_game(const char *path, const player_t *p, int count) {
  FILE *f = fopen(path, "wb");
  if (!f) { perror("save"); return -1; }
  unsigned sum = checksum_crc(p, sizeof *p * count);
  fwrite("SAVE", 1, 4, f);
  fwrite(&count, sizeof count, 1, f);
  fwrite(p, sizeof *p, count, f);
  fwrite(&sum, sizeof sum, 1, f);
  fclose(f);
  return 0;
}

static int load_game(const char *path, player_t *p, int max) {
  FILE *f = fopen(path, "rb");
  char magic[4];
  int count = 0;
  unsigned sum = 0;
  if (!f) return -1;
  if (fread(magic, 1, 4, f) != 4 || memcmp(magic, "SAVE", 4) != 0) { fclose(f); fputs("not a save file\\n", stderr); return -1; }
  if (fread(&count, sizeof count, 1, f) != 1 || count > max) { fclose(f); return -1; }
  if (fread(p, sizeof *p, count, f) != (size_t)count || fread(&sum, sizeof sum, 1, f) != 1) { fclose(f); return -1; }
  fclose(f);
  if (sum != checksum_crc(p, sizeof *p * count)) { fputs("save corrupted\\n", stderr); return -1; }
  return count;
}

int main(int argc, char **argv) {
  int level = 1;
  if (argc < 2) { fprintf(stderr, "usage: %s CONFIG [SAVE]\\n", argv[0]); return 2; }
  build_crc_table();
  load_config(argv[1], &level);
  int count = argc > 2 ? load_game(argv[2], players, 8) : 0;
  if (count <= 0) { count = 2; memset(players, 0, sizeof players); players[0].hp = players[1].hp = 100; }
  for (int frame = 0; frame < level * 60; frame++) {
    ${newer ? "log_frame(frame);" : ""}
    for (int i = 0; i < count; i++) { update_player(&players[i], 1.0f / 60); if (frame % 97 == 0) damage(&players[i], 7); }
  }
  render(players, count);
  printf("checksums %08x %08x\\n", checksum_crc(players, sizeof players), checksum_adler(players, sizeof players));
  return save_game("game.sav", players, count);
}
`;
