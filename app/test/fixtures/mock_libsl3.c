// Minimal C stand-in for the Go core, used only by test/ffi_mock_test.dart to
// exercise the Dart FFI bindings against the exact libsl3 C ABI.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int running = 0;
static int frees = 0;

static char *dup(const char *s) {
  char *p = malloc(strlen(s) + 1);
  strcpy(p, s);
  return p;
}

char *SL3Version(void) { return dup("{\"version\":\"3.0.0-mock\",\"protocol\":\"SL3/1\"}"); }

char *SL3ParseLink(char *link) {
  if (strncmp(link, "sl3://", 6) != 0) return dup("{\"ok\":false,\"error\":\"not an sl3 link\"}");
  char buf[512];
  snprintf(buf, sizeof buf,
           "{\"ok\":true,\"profile\":{\"name\":\"mock\",\"server\":\"%.200s\",\"transport\":\"tls\","
           "\"sni\":\"\",\"subject\":\"ab\",\"plan\":1,\"expiresAt\":0,\"caps\":[\"tcp\"]}}",
           link + 6);
  return dup(buf);
}

char *SL3Start(char *cfg) {
  if (!strstr(cfg, "\"listen\":\"127.0.0.1:1080\"")) return dup("{\"ok\":false,\"error\":\"bad cfg\"}");
  running = 1;
  return dup("{\"ok\":true}");
}

char *SL3Stop(void) { running = 0; return dup("{\"ok\":true}"); }

char *SL3Status(void) {
  char buf[256];
  snprintf(buf, sizeof buf,
           "{\"running\":%s,\"listen\":\"127.0.0.1:1080\",\"up\":10,\"down\":20,\"conns\":%d,"
           "\"since\":1700000000,\"lastError\":\"\"}",
           running ? "true" : "false", frees);
  return dup(buf);
}

char *SL3Probe(char *url, int timeoutMs) {
  char buf[256];
  snprintf(buf, sizeof buf, "{\"ok\":true,\"status\":204,\"latencyMs\":%d}", timeoutMs);
  return dup(buf);
}

void SL3Free(char *p) { frees++; free(p); }
