/*
 * gui.c - PQ-Shard GTK3 front-end.
 *
 * A small front-end over the secret-sharing engine in share.c. Split and
 * combine run on a worker thread so the Argon2id KDF (used when sealing
 * shares under a passphrase) never freezes the UI; a pulsing progress bar
 * animates while it runs.
 */
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sodium.h>
#include "share.h"
#include "secure_buffer.h"

#ifndef PQSHARD_VERSION
#define PQSHARD_VERSION "1.0.2"
#endif
#define APP_ID "org.effjy.PQShard"
#define MAX_PASS 4096

/* Cyber-styled dark theme, matching the Ciphers/PQ tool family. */
static const char *APP_CSS =
    "window, .root {"
    "  background-color: #070b12;"
    "  color: #c8f7ff;"
    "}"
    "headerbar, .titlebar {"
    "  background: linear-gradient(90deg, #0a0f1a, #0e1726, #0a0f1a);"
    "  border-bottom: 1px solid #00e5ff;"
    "  box-shadow: 0 1px 8px rgba(0,229,255,0.35);"
    "  min-height: 32px;"
    "}"
    ".hb-title {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  letter-spacing: 2px;"
    "}"
    "headerbar button {"
    "  padding: 2px 10px; margin: 4px 2px; min-height: 0; min-width: 0;"
    "  letter-spacing: 0;"
    "}"
    "headerbar button.titlebutton {"
    "  padding: 2px; margin: 2px; min-height: 22px; min-width: 22px;"
    "}"
    "label { color: #9fd6e6; font-family: monospace; }"
    ".field-label { color: #5fb4c9; letter-spacing: 1px; }"
    ".brand {"
    "  color: #00e5ff; font-family: monospace; font-weight: bold;"
    "  font-size: 17px; letter-spacing: 4px;"
    "}"
    ".subtitle { color: #3d7d8f; font-size: 9px; letter-spacing: 3px; }"
    "entry {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a;"
    "  border-radius: 4px; padding: 3px 7px; font-family: monospace;"
    "  caret-color: #00e5ff;"
    "}"
    "entry:focus {"
    "  border-color: #00e5ff;"
    "  box-shadow: 0 0 6px rgba(0,229,255,0.6);"
    "}"
    "spinbutton, spinbutton entry {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a; border-radius: 4px; font-family: monospace;"
    "}"
    "spinbutton button { background: #0e1b2b; color: #9fe9ff; border: 0; }"
    "combobox box, combobox button, combobox {"
    "  background-color: #0c1421; color: #d8feff;"
    "  border: 1px solid #14384a; border-radius: 4px;"
    "  font-family: monospace;"
    "}"
    "combobox button:hover { border-color: #00e5ff; }"
    "radiobutton, checkbutton { color: #9fd6e6; font-family: monospace; }"
    "radiobutton check, checkbutton check {"
    "  background-color: #0c1421; border: 1px solid #2a6b80;"
    "}"
    "radiobutton check:checked, checkbutton check:checked {"
    "  background-color: #00e5ff; border-color: #00e5ff;"
    "}"
    "list, list row {"
    "  background-color: #0c1421; color: #cdeffa; font-family: monospace;"
    "}"
    "list row:selected { background-color: #102a3a; }"
    "button {"
    "  background: #0e1b2b; color: #9fe9ff;"
    "  border: 1px solid #1d4c5e; border-radius: 4px;"
    "  padding: 4px 12px; font-family: monospace; letter-spacing: 1px;"
    "}"
    "button:hover {"
    "  border-color: #00e5ff; color: #ffffff;"
    "  box-shadow: 0 0 8px rgba(0,229,255,0.45);"
    "}"
    "button:active { background: #102a3a; }"
    "button:disabled { color: #3a566a; border-color: #16313e; }"
    ".action-button {"
    "  background: linear-gradient(90deg, #00b3c4, #00e5ff);"
    "  color: #02121a; font-weight: bold; letter-spacing: 2px;"
    "  border: 1px solid #00e5ff;"
    "}"
    ".action-button:hover {"
    "  box-shadow: 0 0 14px rgba(0,229,255,0.8);"
    "  color: #000000;"
    "}"
    "progressbar text { color: #9fe9ff; font-family: monospace; font-size: 10px; }"
    "progressbar trough {"
    "  background-color: #0c1421; border: 1px solid #14384a;"
    "  border-radius: 4px; min-height: 14px;"
    "}"
    "progressbar progress {"
    "  background: linear-gradient(90deg, #00b3c4, #39ff14);"
    "  border-radius: 4px; min-height: 14px;"
    "  box-shadow: 0 0 10px rgba(57,255,20,0.6);"
    "}"
    ".status-ok { color: #39ff14; }"
    ".status-err { color: #ff426f; }"
    ".status-run { color: #00e5ff; }"
    "textview, textview text {"
    "  background-color: #0c1421; color: #d8feff; font-family: monospace;"
    "}";

typedef struct Job Job;

typedef struct {
    GtkApplication *gapp;
    GtkWidget *window;

    GtkWidget *radio_split;
    GtkWidget *radio_combine;

    /* split panel */
    GtkWidget *split_box;
    GtkWidget *secret_kind;     /* combo: text / file */
    GtkWidget *secret_text;     /* entry (secure buffer) */
    GtkWidget *secret_text_row;
    GtkWidget *secret_file;     /* entry */
    GtkWidget *secret_file_row;
    GtkWidget *n_spin;
    GtkWidget *k_spin;
    GtkWidget *out_dir;
    GtkWidget *prefix_entry;

    /* combine panel */
    GtkWidget *combine_box;
    GtkWidget *share_list;      /* GtkListBox */
    GPtrArray *share_paths;     /* gchar* owned */
    GtkWidget *combine_target;  /* combo: show text / save file */
    GtkWidget *combine_outfile_row;
    GtkWidget *combine_outfile; /* entry */

    /* shared seal controls */
    GtkWidget *seal_check;
    GtkWidget *pass_entry;      /* secure buffer */
    GtkWidget *pass_row;        /* whole passphrase row (shown only when sealing) */
    GtkWidget *reveal_check;
    GtkWidget *kdf_combo;
    GtkWidget *kdf_row;         /* whole key-strength row (shown only when sealing) */

    GtkWidget *run_button;
    GtkWidget *progress;
    GtkWidget *status;

    guint      pulse_id;
    gboolean   pulsing;
    volatile int window_gone;
    Job * volatile current_job;
} App;

struct Job {
    App  *app;
    int   is_combine;

    /* split */
    int   n, k, seal;
    kdf_level_t level;
    int   secret_is_text;
    uint8_t *secret; size_t secret_len;   /* mlocked, owned */
    char  outdir[4096];
    char  prefix[256];

    /* combine */
    char **paths; int npaths;             /* owned */
    int   to_file;
    char  outfile[4096];

    char  passphrase[MAX_PASS];           /* mlocked */

    /* results */
    int   rc;
    char  err[256];
    char  summary[4608];
    uint8_t *out_secret; size_t out_secret_len; int out_is_text; /* combine */
};

/* ----- small helpers ---------------------------------------------------- */

static void set_status(App *app, const char *cls, const char *text) {
    GtkStyleContext *sc = gtk_widget_get_style_context(app->status);
    gtk_style_context_remove_class(sc, "status-ok");
    gtk_style_context_remove_class(sc, "status-err");
    gtk_style_context_remove_class(sc, "status-run");
    if (cls) gtk_style_context_add_class(sc, cls);
    gtk_label_set_text(GTK_LABEL(app->status), text);
}

static void stop_pulse(App *app) {
    app->pulsing = FALSE;
    if (app->pulse_id) { g_source_remove(app->pulse_id); app->pulse_id = 0; }
}

static void free_app(App *app) {
    stop_pulse(app);
    if (app->share_paths) g_ptr_array_free(app->share_paths, TRUE);
    g_free(app);
}

/* Collapse the window back to fit its currently-visible content. GTK never
 * auto-shrinks a top-level after widgets are hidden, so after any visibility
 * change we keep the width and request height 1 (clamped up to the natural
 * minimum) to drop the dead space the hidden rows/panels would leave behind. */
static void refit_window(App *app) {
    if (!app->window || app->window_gone) return;
    gint w, h;
    gtk_window_get_size(GTK_WINDOW(app->window), &w, &h);
    gtk_window_resize(GTK_WINDOW(app->window), w > 0 ? w : 600, 1);
}

/* Prepare a widget (and its children) to be shown later, but start it hidden
 * and make it immune to the window-wide gtk_widget_show_all(). This way the
 * window's initial natural height excludes it entirely (rather than sizing for
 * it and then leaving dead space once it is hidden). Explicit set_visible()
 * still shows/hides it normally afterwards. */
static void start_hidden(GtkWidget *w) {
    gtk_widget_show_all(w);                 /* mark children as shown */
    gtk_widget_set_no_show_all(w, TRUE);    /* window show_all won't touch it */
    gtk_widget_hide(w);                     /* start collapsed */
}

static GtkWidget *labeled_row(const char *text, GtkWidget *widget, GtkWidget *extra) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new(text);
    gtk_widget_set_size_request(lbl, 120, -1);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_style_context_add_class(gtk_widget_get_style_context(lbl), "field-label");
    gtk_box_pack_start(GTK_BOX(box), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), widget, TRUE, TRUE, 0);
    if (extra) gtk_box_pack_start(GTK_BOX(box), extra, FALSE, FALSE, 0);
    return box;
}

static void msg_dialog(App *app, GtkMessageType type, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char buf[1024]; vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(app->window),
        GTK_DIALOG_MODAL, type, GTK_BUTTONS_OK, "%s", buf);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

/* ----- worker thread ---------------------------------------------------- */

/* Write the n share blobs to outdir/prefix.Xof N.shard. Returns 0 on success
 * and fills job->summary; on error fills job->err. */
static int write_shares(Job *job, uint8_t **blobs, size_t *lens) {
    for (int i = 0; i < job->n; i++) {
        char path[4096];
        if (snprintf(path, sizeof path, "%s/%s.%dof%d.shard",
                     job->outdir, job->prefix, i + 1, job->n) >= (int)sizeof path) {
            snprintf(job->err, sizeof job->err, "Output path is too long.");
            return -1;
        }
        FILE *f = fopen(path, "wb");
        if (!f || fwrite(blobs[i], 1, lens[i], f) != lens[i]) {
            snprintf(job->err, sizeof job->err, "Cannot write share file:\n%.200s", path);
            if (f) fclose(f);
            return -1;
        }
        fclose(f);
    }
    snprintf(job->summary, sizeof job->summary,
             "%d shares written to:\n%s\n\nAny %d reconstruct the secret%s.",
             job->n, job->outdir, job->k,
             job->seal ? " (passphrase also required)" : "");
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || (unsigned long)sz > PQSHARD_MAX_SECRET + 4096) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);
    *out = buf; *outlen = (size_t)sz;
    return 0;
}

static void do_split(Job *job) {
    uint8_t **blobs = calloc((size_t)job->n, sizeof(*blobs));
    size_t *lens = calloc((size_t)job->n, sizeof(*lens));
    if (!blobs || !lens) { snprintf(job->err, sizeof job->err, "Out of memory."); job->rc = -1; free(blobs); free(lens); return; }

    job->rc = pqshard_split(job->secret, job->secret_len, job->secret_is_text,
                            job->n, job->k, job->seal ? job->passphrase : NULL,
                            job->level, blobs, lens, job->err, sizeof job->err);
    if (job->rc == 0) job->rc = write_shares(job, blobs, lens);

    for (int i = 0; i < job->n; i++) free(blobs[i]);
    free(blobs); free(lens);
}

static void do_combine(Job *job) {
    const uint8_t **blobs = calloc((size_t)job->npaths, sizeof(*blobs));
    size_t *lens = calloc((size_t)job->npaths, sizeof(*lens));
    if (!blobs || !lens) { snprintf(job->err, sizeof job->err, "Out of memory."); job->rc = -1; free(blobs); free(lens); return; }

    job->rc = 0;
    for (int i = 0; i < job->npaths; i++) {
        uint8_t *b = NULL; size_t L = 0;
        if (read_file(job->paths[i], &b, &L) != 0) {
            snprintf(job->err, sizeof job->err, "Cannot read share file:\n%.200s", job->paths[i]);
            job->rc = -1; break;
        }
        blobs[i] = b; lens[i] = L;
    }

    if (job->rc == 0) {
        job->rc = pqshard_combine(blobs, lens, job->npaths,
                                  *job->passphrase ? job->passphrase : NULL,
                                  &job->out_secret, &job->out_secret_len,
                                  &job->out_is_text, job->err, sizeof job->err);
    }
    if (job->rc == 0) {
        if (job->to_file) {
            FILE *f = fopen(job->outfile, "wb");
            if (!f || fwrite(job->out_secret, 1, job->out_secret_len, f) != job->out_secret_len) {
                snprintf(job->err, sizeof job->err, "Cannot write output file:\n%.200s", job->outfile);
                if (f) fclose(f);
                job->rc = -1;
            } else {
                fclose(f);
                snprintf(job->summary, sizeof job->summary,
                         "Recovered %zu-byte secret written to:\n%s",
                         job->out_secret_len, job->outfile);
            }
            pqshard_free_secret(job->out_secret, job->out_secret_len);
            job->out_secret = NULL;
        }
        /* else: keep out_secret for the on-screen text dialog (freed there). */
    }

    for (int i = 0; i < job->npaths; i++) free((void *)blobs[i]);
    free(blobs); free(lens);
}

static void job_free(Job *job) {
    if (job->secret) { sodium_munlock(job->secret, job->secret_len); free(job->secret); }
    sodium_munlock(job->passphrase, sizeof job->passphrase);
    if (job->paths) {
        for (int i = 0; i < job->npaths; i++) free(job->paths[i]);
        free(job->paths);
    }
    if (job->out_secret) pqshard_free_secret(job->out_secret, job->out_secret_len);
    g_free(job);
}

/* Show a recovered text secret in a selectable, modal dialog. */
static void show_secret_dialog(App *app, Job *job) {
    GtkWidget *d = gtk_dialog_new_with_buttons("Recovered secret",
        GTK_WINDOW(app->window), GTK_DIALOG_MODAL,
        "_Copy", 1, "_Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(d), 460, 200);
    GtkWidget *area = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(area), 10);

    GtkWidget *lbl = gtk_label_new("The secret has been reconstructed:");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(area), lbl, FALSE, FALSE, 4);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(sw, -1, 110);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    GtkWidget *tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_CHAR);
    GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));
    gtk_text_buffer_set_text(tb, (const char *)job->out_secret,
                             (int)job->out_secret_len);
    gtk_container_add(GTK_CONTAINER(sw), tv);
    gtk_box_pack_start(GTK_BOX(area), sw, TRUE, TRUE, 4);
    gtk_widget_show_all(area);

    for (;;) {
        int resp = gtk_dialog_run(GTK_DIALOG(d));
        if (resp == 1) {
            GtkClipboard *cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
            gtk_clipboard_set_text(cb, (const char *)job->out_secret,
                                   (int)job->out_secret_len);
        } else break;
    }
    gtk_widget_destroy(d);
}

static gboolean job_finished_idle(gpointer data) {
    Job *job = data;
    App *app = job->app;

    app->current_job = NULL;
    stop_pulse(app);

    if (app->window_gone) {
        job_free(job);
        g_application_release(G_APPLICATION(app->gapp));
        free_app(app);
        return G_SOURCE_REMOVE;
    }

    gtk_widget_set_sensitive(app->run_button, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), job->rc == 0 ? 1.0 : 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), job->rc == 0 ? "done" : "idle");

    if (job->rc == 0) {
        if (job->is_combine && !job->to_file) {
            set_status(app, "status-ok", "\xE2\x9C\x94 Secret reconstructed.");
            show_secret_dialog(app, job);
        } else {
            gchar *m = g_strdup_printf("\xE2\x9C\x94 %s", job->summary);
            set_status(app, "status-ok", m);
            g_free(m);
        }
    } else {
        gchar *m = g_strdup_printf("\xE2\x9C\x96 %s", job->err);
        set_status(app, "status-err", m);
        g_free(m);
        msg_dialog(app, GTK_MESSAGE_ERROR, "%s", job->err);
    }

    job_free(job);
    g_application_release(G_APPLICATION(app->gapp));
    return G_SOURCE_REMOVE;
}

static gboolean pulse_cb(gpointer data) {
    App *app = data;
    if (!app->pulsing || app->window_gone) { app->pulse_id = 0; return G_SOURCE_REMOVE; }
    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(app->progress));
    return G_SOURCE_CONTINUE;
}

static gpointer worker_thread(gpointer data) {
    Job *job = data;
    if (job->is_combine) do_combine(job);
    else                 do_split(job);
    g_idle_add(job_finished_idle, job);
    return NULL;
}

/* ----- UI callbacks ----------------------------------------------------- */

static void on_reveal_toggled(GtkToggleButton *btn, gpointer user) {
    App *app = user;
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), gtk_toggle_button_get_active(btn));
}

static void sync_seal_sensitivity(App *app) {
    gboolean on = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->seal_check));
    /* The passphrase and key-strength rows only apply when sealing; hide them
     * otherwise so the default window stays compact. */
    gtk_widget_set_visible(app->pass_row, on);
    gtk_widget_set_visible(app->kdf_row, on);
    refit_window(app);
}

static void on_seal_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn; sync_seal_sensitivity(user);
}

static void on_secret_kind_changed(GtkComboBox *combo, gpointer user) {
    App *app = user;
    const gchar *id = gtk_combo_box_get_active_id(combo);
    gboolean is_file = id && !strcmp(id, "file");
    gtk_widget_set_visible(app->secret_text_row, !is_file);
    gtk_widget_set_visible(app->secret_file_row, is_file);
    refit_window(app);
}

static void on_combine_target_changed(GtkComboBox *combo, gpointer user) {
    App *app = user;
    const gchar *id = gtk_combo_box_get_active_id(combo);
    gboolean to_file = id && !strcmp(id, "file");
    gtk_widget_set_visible(app->combine_outfile_row, to_file);
    refit_window(app);
}

static void browse_into_entry(App *app, GtkWidget *entry,
                              GtkFileChooserAction action, const char *title) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, GTK_WINDOW(app->window),
        action, "_Cancel", GTK_RESPONSE_CANCEL, "_Select", GTK_RESPONSE_ACCEPT, NULL);
    if (action == GTK_FILE_CHOOSER_ACTION_SAVE)
        gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        gtk_entry_set_text(GTK_ENTRY(entry), f);
        g_free(f);
    }
    gtk_widget_destroy(dlg);
}

static void on_browse_secret_file(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_into_entry(app, app->secret_file, GTK_FILE_CHOOSER_ACTION_OPEN, "Select secret file");
}
static void on_browse_outdir(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_into_entry(app, app->out_dir, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "Select output folder");
}
static void on_browse_outfile(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    browse_into_entry(app, app->combine_outfile, GTK_FILE_CHOOSER_ACTION_SAVE, "Save recovered secret as");
}

/* Append a share path to the list (model + a row label). */
static void add_share_path(App *app, const char *path) {
    g_ptr_array_add(app->share_paths, g_strdup(path));
    GtkWidget *row = gtk_label_new(path);
    gtk_label_set_xalign(GTK_LABEL(row), 0.0);
    gtk_label_set_ellipsize(GTK_LABEL(row), PANGO_ELLIPSIZE_START);
    gtk_widget_set_margin_start(row, 6); gtk_widget_set_margin_end(row, 6);
    gtk_widget_set_margin_top(row, 2); gtk_widget_set_margin_bottom(row, 2);
    gtk_list_box_insert(GTK_LIST_BOX(app->share_list), row, -1);
    gtk_widget_show(row);
}

static void on_add_shares(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    GtkWidget *dlg = gtk_file_chooser_dialog_new("Add share files",
        GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL, "_Add", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dlg), TRUE);
    GtkFileFilter *filt = gtk_file_filter_new();
    gtk_file_filter_set_name(filt, "PQ-Shard shares (*.shard)");
    gtk_file_filter_add_pattern(filt, "*.shard");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), filt);
    GtkFileFilter *all = gtk_file_filter_new();
    gtk_file_filter_set_name(all, "All files");
    gtk_file_filter_add_pattern(all, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg), all);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        GSList *files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dlg));
        for (GSList *l = files; l; l = l->next) {
            add_share_path(app, (const char *)l->data);
            g_free(l->data);
        }
        g_slist_free(files);
    }
    gtk_widget_destroy(dlg);
}

static void on_clear_shares(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    g_ptr_array_set_size(app->share_paths, 0);
    GList *rows = gtk_container_get_children(GTK_CONTAINER(app->share_list));
    for (GList *l = rows; l; l = l->next) gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(rows);
}

static void on_mode_toggled(GtkToggleButton *btn, gpointer user) {
    (void)btn; App *app = user;
    gboolean split = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_split));
    gtk_widget_set_visible(app->split_box, split);
    gtk_widget_set_visible(app->combine_box, !split);
    gtk_button_set_label(GTK_BUTTON(app->run_button), split ? "SPLIT" : "COMBINE");
    refit_window(app);
}

/* Gather the secret bytes for a split into a freshly malloc'd buffer. Returns
 * 0 on success; on validation failure shows a dialog and returns -1. */
static int gather_secret(App *app, uint8_t **out, size_t *outlen, int *is_text) {
    const gchar *kind = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->secret_kind));
    if (kind && !strcmp(kind, "file")) {
        const char *path = gtk_entry_get_text(GTK_ENTRY(app->secret_file));
        if (!path || !*path) { msg_dialog(app, GTK_MESSAGE_WARNING, "Choose a secret file to split."); return -1; }
        if (read_file(path, out, outlen) != 0) {
            msg_dialog(app, GTK_MESSAGE_ERROR, "Cannot read the secret file (or it is too large)."); return -1;
        }
        if (*outlen == 0) { free(*out); msg_dialog(app, GTK_MESSAGE_WARNING, "The secret file is empty."); return -1; }
        *is_text = 0;
        return 0;
    }
    const char *txt = gtk_entry_get_text(GTK_ENTRY(app->secret_text));
    size_t L = txt ? strlen(txt) : 0;
    if (L == 0) { msg_dialog(app, GTK_MESSAGE_WARNING, "Type the secret text to split."); return -1; }
    uint8_t *buf = malloc(L);
    if (!buf) { msg_dialog(app, GTK_MESSAGE_ERROR, "Out of memory."); return -1; }
    memcpy(buf, txt, L);
    *out = buf; *outlen = L; *is_text = 1;
    return 0;
}

static void start_job(App *app, Job *job) {
    gtk_widget_set_sensitive(app->run_button, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress),
                              job->seal || job->is_combine ? "working\xE2\x80\xA6" : "splitting\xE2\x80\xA6");
    set_status(app, "status-run", "\xE2\x96\xB6 Working\xE2\x80\xA6");
    app->pulsing = TRUE;
    if (app->pulse_id == 0) app->pulse_id = g_timeout_add(110, pulse_cb, app);

    app->current_job = job;
    g_application_hold(G_APPLICATION(app->gapp));

    GError *gerr = NULL;
    GThread *t = g_thread_try_new("pqshard-worker", worker_thread, job, &gerr);
    if (!t) {
        g_application_release(G_APPLICATION(app->gapp));
        app->current_job = NULL;
        stop_pulse(app);
        gtk_widget_set_sensitive(app->run_button, TRUE);
        set_status(app, "status-err", "\xE2\x9C\x96 Could not start worker thread.");
        job_free(job);
        if (gerr) g_error_free(gerr);
        return;
    }
    g_thread_unref(t);
}

static void on_run(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    gboolean split = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->radio_split));
    gboolean seal = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->seal_check));
    const char *pw = gtk_entry_get_text(GTK_ENTRY(app->pass_entry));

    if (seal && (!pw || !*pw)) {
        msg_dialog(app, GTK_MESSAGE_WARNING, "Sealing is on: enter a passphrase (or turn sealing off).");
        return;
    }
    if (pw && strlen(pw) >= MAX_PASS) {
        msg_dialog(app, GTK_MESSAGE_WARNING, "Passphrase is too long."); return;
    }

    if (split) {
        int n = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->n_spin));
        int k = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(app->k_spin));
        if (k < 2 || n < k) {
            msg_dialog(app, GTK_MESSAGE_WARNING, "Threshold must be at least 2 and no more than the number of shares.");
            return;
        }
        const char *outdir = gtk_entry_get_text(GTK_ENTRY(app->out_dir));
        const char *prefix = gtk_entry_get_text(GTK_ENTRY(app->prefix_entry));
        if (!outdir || !*outdir) { msg_dialog(app, GTK_MESSAGE_WARNING, "Choose an output folder."); return; }
        if (!prefix || !*prefix) prefix = "secret";
        if (strlen(outdir) >= sizeof ((Job *)0)->outdir || strlen(prefix) >= sizeof ((Job *)0)->prefix) {
            msg_dialog(app, GTK_MESSAGE_WARNING, "Output folder or prefix is too long."); return;
        }

        uint8_t *secret = NULL; size_t slen = 0; int is_text = 0;
        if (gather_secret(app, &secret, &slen, &is_text) != 0) return;

        Job *job = g_new0(Job, 1);
        sodium_mlock(job->passphrase, sizeof job->passphrase);
        job->app = app; job->is_combine = 0;
        job->n = n; job->k = k; job->seal = seal ? 1 : 0;
        const gchar *kid = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->kdf_combo));
        job->level = kid ? (kdf_level_t)atoi(kid) : KDF_MEDIUM;
        job->secret = secret; job->secret_len = slen;
        sodium_mlock(job->secret, slen);
        job->secret_is_text = is_text;
        g_strlcpy(job->outdir, outdir, sizeof job->outdir);
        g_strlcpy(job->prefix, prefix, sizeof job->prefix);
        if (seal) g_strlcpy(job->passphrase, pw, sizeof job->passphrase);
        start_job(app, job);
    } else {
        if (app->share_paths->len < 2) {
            msg_dialog(app, GTK_MESSAGE_WARNING, "Add at least two share files to combine.");
            return;
        }
        const gchar *tgt = gtk_combo_box_get_active_id(GTK_COMBO_BOX(app->combine_target));
        int to_file = tgt && !strcmp(tgt, "file");
        const char *outfile = gtk_entry_get_text(GTK_ENTRY(app->combine_outfile));
        if (to_file && (!outfile || !*outfile)) {
            msg_dialog(app, GTK_MESSAGE_WARNING, "Choose where to save the recovered secret."); return;
        }
        if (to_file && strlen(outfile) >= sizeof ((Job *)0)->outfile) {
            msg_dialog(app, GTK_MESSAGE_WARNING, "Output path is too long."); return;
        }

        Job *job = g_new0(Job, 1);
        sodium_mlock(job->passphrase, sizeof job->passphrase);
        job->app = app; job->is_combine = 1;
        job->npaths = app->share_paths->len;
        job->paths = calloc((size_t)job->npaths, sizeof(char *));
        for (int i = 0; i < job->npaths; i++)
            job->paths[i] = g_strdup((const char *)app->share_paths->pdata[i]);
        job->to_file = to_file;
        if (to_file) g_strlcpy(job->outfile, outfile, sizeof job->outfile);
        if (pw) g_strlcpy(job->passphrase, pw, sizeof job->passphrase);
        start_job(app, job);
    }
}

static void on_about(GtkButton *b, gpointer user) {
    (void)b; App *app = user;
    const gchar *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
    const gchar *desc =
        "PQ-Shard splits a secret into N shares so that any K of them "
        "reconstruct it and fewer reveal nothing.\n\n"
        "Features:\n"
        "\xE2\x80\xA2 Shamir's Secret Sharing over GF(2^8) (information-theoretic)\n"
        "\xE2\x80\xA2 Split a passphrase, a key, or any file\n"
        "\xE2\x80\xA2 A verification tag is split with the secret, so a good\n"
        "  reconstruction is confirmed without leaking below the threshold\n"
        "\xE2\x80\xA2 Optional post-quantum sealing: each share encrypted under a\n"
        "  passphrase via Kyber-1024 + X448 and Argon2id\n"
        "\xE2\x80\xA2 Hardened memory: secrets held in locked, non-dumpable RAM";

    GtkWidget *d = gtk_about_dialog_new();
    GtkAboutDialog *ad = GTK_ABOUT_DIALOG(d);
    gtk_about_dialog_set_program_name(ad, "PQ-Shard");
    gtk_about_dialog_set_version(ad, "v" PQSHARD_VERSION);
    gtk_about_dialog_set_comments(ad, desc);
    gtk_about_dialog_set_authors(ad, authors);
    gtk_about_dialog_set_copyright(ad, "© 2026 Jean-Francois Lachance-Caumartin");
    gtk_about_dialog_set_license_type(ad, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_logo_icon_name(ad, "pqshard");
    gtk_window_set_transient_for(GTK_WINDOW(d), GTK_WINDOW(app->window));
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static void on_window_destroy(GtkWidget *w, gpointer user) {
    (void)w; App *app = user;
    app->window_gone = 1;
    Job *job = app->current_job;
    if (job) {
        /* A worker is running; it owns app's lifetime and frees it from
         * job_finished_idle. (Split/combine are not cancellable mid-KDF.) */
    } else {
        free_app(app);
    }
}

static void load_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_data(p, APP_CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(p), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

/* ----- build the split / combine panels --------------------------------- */

static GtkWidget *build_split_panel(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    app->secret_kind = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->secret_kind), "text", "Text (passphrase / key string)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->secret_kind), "file", "File contents");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->secret_kind), "text");
    g_signal_connect(app->secret_kind, "changed", G_CALLBACK(on_secret_kind_changed), app);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("Secret:", app->secret_kind, NULL), FALSE, FALSE, 0);

    GtkEntryBuffer *sbuf = secure_entry_buffer_new();
    app->secret_text = gtk_entry_new_with_buffer(sbuf);
    g_object_unref(sbuf);
    gtk_entry_set_visibility(GTK_ENTRY(app->secret_text), FALSE);
    app->secret_text_row = labeled_row("Secret text:", app->secret_text, NULL);
    gtk_box_pack_start(GTK_BOX(box), app->secret_text_row, FALSE, FALSE, 0);

    app->secret_file = gtk_entry_new();
    GtkWidget *sfb = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(sfb, "clicked", G_CALLBACK(on_browse_secret_file), app);
    app->secret_file_row = labeled_row("Secret file:", app->secret_file, sfb);
    gtk_box_pack_start(GTK_BOX(box), app->secret_file_row, FALSE, FALSE, 0);

    GtkWidget *nk = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->n_spin = gtk_spin_button_new_with_range(2, 255, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->n_spin), 5);
    app->k_spin = gtk_spin_button_new_with_range(2, 255, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->k_spin), 3);
    GtkWidget *nl = gtk_label_new("Total shares:");
    gtk_style_context_add_class(gtk_widget_get_style_context(nl), "field-label");
    GtkWidget *kl = gtk_label_new("  Threshold:");
    gtk_style_context_add_class(gtk_widget_get_style_context(kl), "field-label");
    gtk_box_pack_start(GTK_BOX(nk), nl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(nk), app->n_spin, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(nk), kl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(nk), app->k_spin, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("Scheme (K of N):", nk, NULL), FALSE, FALSE, 0);

    app->out_dir = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->out_dir), g_get_home_dir());
    GtkWidget *odb = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(odb, "clicked", G_CALLBACK(on_browse_outdir), app);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("Output folder:", app->out_dir, odb), FALSE, FALSE, 0);

    app->prefix_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->prefix_entry), "secret");
    gtk_box_pack_start(GTK_BOX(box), labeled_row("File prefix:", app->prefix_entry, NULL), FALSE, FALSE, 0);

    return box;
}

static GtkWidget *build_combine_panel(App *app) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);

    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(sw, -1, 84);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    app->share_list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->share_list), GTK_SELECTION_NONE);
    gtk_container_add(GTK_CONTAINER(sw), app->share_list);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("Shares:", sw, NULL), FALSE, FALSE, 0);

    GtkWidget *btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *add = gtk_button_new_with_label("Add shares\xE2\x80\xA6");
    g_signal_connect(add, "clicked", G_CALLBACK(on_add_shares), app);
    GtkWidget *clr = gtk_button_new_with_label("Clear");
    g_signal_connect(clr, "clicked", G_CALLBACK(on_clear_shares), app);
    gtk_box_pack_start(GTK_BOX(btns), add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btns), clr, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("", btns, NULL), FALSE, FALSE, 0);

    app->combine_target = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->combine_target), "text", "Show recovered text");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->combine_target), "file", "Save to file");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->combine_target), "text");
    g_signal_connect(app->combine_target, "changed", G_CALLBACK(on_combine_target_changed), app);
    gtk_box_pack_start(GTK_BOX(box), labeled_row("Recover to:", app->combine_target, NULL), FALSE, FALSE, 0);

    app->combine_outfile = gtk_entry_new();
    GtkWidget *ofb = gtk_button_new_with_label("Browse\xE2\x80\xA6");
    g_signal_connect(ofb, "clicked", G_CALLBACK(on_browse_outfile), app);
    app->combine_outfile_row = labeled_row("Save as:", app->combine_outfile, ofb);
    gtk_box_pack_start(GTK_BOX(box), app->combine_outfile_row, FALSE, FALSE, 0);

    return box;
}

static void activate(GtkApplication *gapp, gpointer user) {
    (void)user;
    App *app = g_new0(App, 1);
    app->gapp = gapp;
    app->share_paths = g_ptr_array_new_with_free_func(g_free);

    load_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "PQ-Shard");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 600, -1);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "pqshard");
    gtk_window_set_position(GTK_WINDOW(app->window), GTK_WIN_POS_CENTER);

    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *title_lbl = gtk_label_new("PQ-SHARD  \xC2\xB7  v" PQSHARD_VERSION);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_NONE);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "hb-title");
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(hb), title_lbl);
    GtkWidget *hb_about = gtk_button_new_with_label("About");
    g_signal_connect(hb_about, "clicked", G_CALLBACK(on_about), app);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), hb_about);
    gtk_window_set_titlebar(GTK_WINDOW(app->window), hb);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_style_context_add_class(gtk_widget_get_style_context(root), "root");
    gtk_container_set_border_width(GTK_CONTAINER(root), 10);
    gtk_container_add(GTK_CONTAINER(app->window), root);

    GtkWidget *brand = gtk_label_new("\xE2\xAC\xA2 PQ-SHARD");
    gtk_label_set_xalign(GTK_LABEL(brand), 0.5);
    gtk_style_context_add_class(gtk_widget_get_style_context(brand), "brand");
    gtk_box_pack_start(GTK_BOX(root), brand, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);

    /* Mode */
    GtkWidget *mode_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    app->radio_split = gtk_radio_button_new_with_label(NULL, "Split a secret");
    app->radio_combine = gtk_radio_button_new_with_label_from_widget(
        GTK_RADIO_BUTTON(app->radio_split), "Combine shares");
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_split, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(mode_box), app->radio_combine, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Mode:", mode_box, NULL), FALSE, FALSE, 0);

    /* Panels */
    app->split_box = build_split_panel(app);
    app->combine_box = build_combine_panel(app);
    gtk_box_pack_start(GTK_BOX(root), app->split_box, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), app->combine_box, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(root), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 2);

    /* Sealing (shared by both modes) */
    app->seal_check = gtk_check_button_new_with_label(
        "Seal shares with a passphrase (Kyber-1024 + X448)");
    g_signal_connect(app->seal_check, "toggled", G_CALLBACK(on_seal_toggled), app);
    gtk_box_pack_start(GTK_BOX(root), labeled_row("Sealing:", app->seal_check, NULL), FALSE, FALSE, 0);

    GtkEntryBuffer *pbuf = secure_entry_buffer_new();
    app->pass_entry = gtk_entry_new_with_buffer(pbuf);
    g_object_unref(pbuf);
    gtk_entry_set_visibility(GTK_ENTRY(app->pass_entry), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(app->pass_entry), GTK_INPUT_PURPOSE_PASSWORD);
    app->reveal_check = gtk_check_button_new_with_label("Reveal");
    g_signal_connect(app->reveal_check, "toggled", G_CALLBACK(on_reveal_toggled), app);
    app->pass_row = labeled_row("Passphrase:", app->pass_entry, app->reveal_check);
    gtk_box_pack_start(GTK_BOX(root), app->pass_row, FALSE, FALSE, 0);

    app->kdf_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "0", "Basic (256 MiB)");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "1", "Medium (1 GiB, parallel) — minimum");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(app->kdf_combo), "2", "Strong (4 GiB, parallel)");
    gtk_combo_box_set_active_id(GTK_COMBO_BOX(app->kdf_combo), "1");
    app->kdf_row = labeled_row("Key strength:", app->kdf_combo, NULL);
    gtk_box_pack_start(GTK_BOX(root), app->kdf_row, FALSE, FALSE, 0);

    /* Action + progress + status */
    app->run_button = gtk_button_new_with_label("SPLIT");
    gtk_widget_set_hexpand(app->run_button, TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(app->run_button), "action-button");
    g_signal_connect(app->run_button, "clicked", G_CALLBACK(on_run), app);
    gtk_box_pack_start(GTK_BOX(root), app->run_button, FALSE, FALSE, 3);

    app->progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(app->progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(app->progress), "idle");
    gtk_box_pack_start(GTK_BOX(root), app->progress, FALSE, FALSE, 0);
    app->status = gtk_label_new("Ready.");
    gtk_label_set_xalign(GTK_LABEL(app->status), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(app->status), TRUE);
    gtk_box_pack_start(GTK_BOX(root), app->status, FALSE, FALSE, 0);

    g_signal_connect(app->radio_split, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->radio_combine, "toggled", G_CALLBACK(on_mode_toggled), app);
    g_signal_connect(app->window, "destroy", G_CALLBACK(on_window_destroy), app);

    /* Keep the panels/rows that start hidden out of the window's initial
     * show_all, so its first natural height fits only the visible content
     * (the inactive Combine panel is ~200px on its own). */
    start_hidden(app->combine_box);
    start_hidden(app->combine_outfile_row);
    start_hidden(app->secret_file_row);
    start_hidden(app->pass_row);
    start_hidden(app->kdf_row);

    gtk_widget_show_all(app->window);

    /* Apply initial visibility (after show_all, which would reveal everything). */
    on_mode_toggled(NULL, app);
    on_secret_kind_changed(GTK_COMBO_BOX(app->secret_kind), app);
    on_combine_target_changed(GTK_COMBO_BOX(app->combine_target), app);
    sync_seal_sensitivity(app);

    /* gtk_widget_show_all() sized the window with every panel visible; GTK does
     * not auto-shrink a top-level once sized, so after hiding the inactive
     * panels we collapse the window back to fit just the visible content
     * (requesting height 1 clamps up to the natural minimum). Without this the
     * window keeps the taller "everything visible" height, leaving dead space
     * below the status line. */
    gtk_window_resize(GTK_WINDOW(app->window), 600, 1);
}

int main(int argc, char **argv) {
    if (pqshard_init() != 0) {
        g_printerr("Failed to initialise crypto library.\n");
        return 1;
    }
    GtkApplication *gapp = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(gapp, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(gapp), argc, argv);
    g_object_unref(gapp);
    return status;
}
