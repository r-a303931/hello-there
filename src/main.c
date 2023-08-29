#define _GNU_SOURCE
#include <auparse.h>
#include <errno.h>
#include <fcntl.h>
#include <libaudit.h>
#include <libnotify/notification.h>
#include <libnotify/notify.h>
#include <linux/audit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

#define FILE_NAME "/etc/SUPER_SECRET_STUFF/README"

char *TAUNTS[] = {"Get yo hands off mah files!",
                  "Now you're really getting to annoy me...",
                  "I *will* reboot your computer!"};

static void handle_event(int *count, char *name, char *tty) {
  int local_count = *count;
  *count = local_count + 1;

  if (local_count > 2) {
    char *reboot[] = {"sudo", "reboot", NULL};
    execvp("sudo", reboot);
  }

  FILE *fcount;
  fcount = fopen("/count", "w");
  fprintf(fcount, "%d\n", local_count);
  fclose(fcount);

  int pid = fork();
  if (pid == 0) {
    if (!strncmp(tty, "tty", 3)) {
      char figletcmd[128];
      char *cmd[] = {"-c", figletcmd, NULL};
      snprintf(cmd[1], sizeof(figletcmd), "echo %s | figlet | wall",
               TAUNTS[local_count]);
      execvp("bash", cmd);
    } else {
      char bus[32], ptspath[32];
      struct stat statbuf;

      snprintf(ptspath, sizeof(ptspath), "/dev/pts/%s", &tty[3]);
      stat(ptspath, &statbuf);

      const char *note = "Handsy Detection Subsystem";
      notify_init(note);
      snprintf(bus, sizeof(bus), "unix:path=/run/user/%d/bus", statbuf.st_uid);

      setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1);
      setresuid(statbuf.st_uid, statbuf.st_uid, statbuf.st_uid);

      NotifyNotification *n =
          notify_notification_new(note, TAUNTS[local_count], NULL);
      notify_notification_set_urgency(n, NOTIFY_URGENCY_CRITICAL);
      notify_notification_set_timeout(n, 5000);
      notify_notification_show(n, NULL);
      g_object_unref(G_OBJECT(n));
    }
  }
}

static void find_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
                       void *user_data) {
  if (cb_event_type != AUPARSE_CB_EVENT_READY)
    return;

  int *count = (int *)user_data;

  auparse_first_record(au);

  char *name = NULL, *tty = NULL;

  do {
    int type = auparse_get_type(au);
    auparse_first_field(au);

    if (type == AUDIT_PATH) {
      if (auparse_find_field(au, "name")) {
        name = strdup(auparse_interpret_field(au));
      }
    } else if (type == AUDIT_SYSCALL) {
      if (auparse_find_field(au, "tty")) {
        tty = strdup(auparse_get_field_str(au));
      }
    } else if (type == AUDIT_CWD) {
    } else if (type == AUDIT_PROCTITLE) {
    }

    if (name != NULL && tty != NULL) {
      if (!strcmp(name, FILE_NAME)) {
        handle_event(count, name, tty);
      }
      free(name);
      free(tty);
      name = NULL;
      tty = NULL;
    }
  } while (auparse_next_record(au) > 0);
}

int main(int argc, char **argv) {
  auparse_state_t *au = NULL;
  char tmp[MAX_AUDIT_MESSAGE_LENGTH + 1];
  int check_count = 0;

  au = auparse_init(AUSOURCE_FEED, 0);
  auparse_add_callback(au, find_event, (void *)&check_count, NULL);

  do {
    int retval = -1;
    fd_set read_mask;

    FD_ZERO(&read_mask);
    FD_SET(0, &read_mask);

    do {
      retval = select(1, &read_mask, NULL, NULL, NULL);
    } while (retval == -1 && errno == EINTR);

    if (retval > 0) {
      if (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin)) {
        auparse_feed(au, tmp, strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));
      }
    } else if (retval == 0) {
      auparse_flush_feed(au);
    }

    if (feof(stdin)) {
      break;
    }
  } while (1);

  auparse_flush_feed(au);
  auparse_destroy(au);

  return 0;
}
