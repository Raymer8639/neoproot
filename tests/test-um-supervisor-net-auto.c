/* Exercise only production one-shot wrappers, without starting a traced UML. */
#include "../src/backend/um_supervisor.c"

/* um_write_wrapper references this even when session_mode is false.
 * Reject an accidental session path rather than embedding a fake guest loop
 * or requiring the build-generated um_session_loop.h in a clean checkout.
 * Persistent sessions are deliberately outside this regression's coverage. */
int um_session_write_loop(int fd)
{
    (void)fd;
    fprintf(stderr, "FAIL: net-auto test covers one-shot wrappers only\n");
    errno = ENOTSUP;
    return -1;
}

int main(int argc, char **argv)
{
    UmConfig config = {0};
    char *guest_argv[] = {"/bin/true", NULL};

    if (argc != 3)
        return 2;
    config.network_auto = true;
    snprintf(config.net_addr, sizeof(config.net_addr), "%s", "10.44.0.9");
    config.net_mask = "24";
    snprintf(config.net_gateway, sizeof(config.net_gateway), "%s", "10.44.0.1");
    return um_write_wrapper(argv[1], "/", "/unused-status", &config,
                            strcmp(argv[2], "ext4") == 0, false,
                            1, guest_argv) < 0;
}
