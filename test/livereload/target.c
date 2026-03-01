/* Live Reload Test Target
 *
 * This is a simple program that we'll patch in real-time.
 * The get_message() function will be hot-patched when source changes.
 */

#include <stdio.h>
#include <unistd.h>

/* This function will be hot-patched */
const char* get_message(void) {
    return "Hello from original code!";
}

/* This function calls the patchable one */
void print_message(void) {
    printf("[target] %s\n", get_message());
    fflush(stdout);
}

int main(int argc, char **argv) {
    printf("[target] Live reload test target started (PID: %d)\n", getpid());
    printf("[target] Modify target.c and save to see hot-patching in action\n");
    printf("[target] Press Ctrl+C to exit\n\n");

    /* Loop printing the message every 2 seconds */
    while (1) {
        print_message();
        sleep(2);
    }

    return 0;
}
