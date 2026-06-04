#ifndef INCLUDE_MAIN_H
#define INCLUDE_MAIN_H

#include <gtk/gtk.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <glib.h>
#include <errno.h>
#include "global.h"

// Function declarations
void connect_ssh(AppData *data);
void disconnect_ssh(AppData *data);

void refresh_local_directory(AppData *data);

void refresh_remote_directory(AppData *data);
void refresh_remote_directory_sftp(AppData *data);
void refresh_remote_directory_scp(AppData *data);

void create_local_directory(AppData *data, const char *dirname);

void create_remote_directory(AppData *data, const char *dirname);
void create_remote_directory_sftp(AppData *data, const char *dirname);
void create_remote_directory_scp(AppData *data, const char *dirname);

void copy_file_to_remote(AppData *data, const char *local_path, const char *remote_path);
void copy_file_to_remote_sftp(AppData *data, const char *local_path, const char *remote_path);
void copy_file_to_remote_scp(AppData *data, const char *local_path, const char *remote_path);

void copy_file_from_remote(AppData *data, const char *remote_path, const char *local_path);
void copy_file_from_remote_sftp(AppData *data, const char *remote_path, const char *local_path);
void copy_file_from_remote_scp(AppData *data, const char *remote_path, const char *local_path);

void copy_directory_to_remote(AppData *data, const char *local_path, const char *remote_path);
void copy_directory_to_remote_sftp(AppData *data, const char *local_path, const char *remote_path);
void copy_directory_to_remote_scp(AppData *data, const char *local_path, const char *remote_path);

void copy_directory_from_remote(AppData *data, const char *remote_path, const char *local_path);
void copy_directory_from_remote_sftp(AppData *data, const char *remote_path, const char *local_path);
void copy_directory_from_remote_scp(AppData *data, const char *remote_path, const char *local_path);

void delete_local_file(AppData *data, const char *path);

void delete_local_directory_recursive(const char *path);

void delete_remote_file(AppData *data, const char *path);
void delete_remote_file_sftp(AppData *data, const char *path);
void delete_remote_file_scp(AppData *data, const char *path);

void delete_remote_directory(AppData *data, const char *path);
void delete_remote_directory_sftp(AppData *data, const char *path);
void delete_remote_directory_scp(AppData *data, const char *path);

void show_progress_bar(AppData *data);
void hide_progress_bar(AppData *data);
void update_progress_bar(AppData *data, double fraction, const char *text);

/////////////////////////////////////////////////////////////////////////////////////////////////////

void save_connection(AppData *data);
void load_connection(AppData *data, const char *name);
void load_connection_dialog(AppData *data);
gboolean load_connection_dialog_func(gpointer data);
void delete_connection(const char *name);
GList* get_saved_connection_names(void);

char* get_config_file_path(void);
char* prompt_password(char* title_text, char* label_text, gboolean show_text);

void on_browse_key_file_clicked(GtkWidget *widget, gpointer data);
void on_support_clicked(GtkWidget *widget, gpointer data);
void on_mkdir_local_clicked(GtkWidget *widget, gpointer data);
void on_mkdir_remote_clicked(GtkWidget *widget, gpointer data);
void on_delete_local_clicked(GtkWidget *widget, gpointer data);
void on_delete_remote_clicked(GtkWidget *widget, gpointer data);
gboolean on_local_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data);
gboolean on_remote_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data);

void on_local_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data);
void on_local_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data);
void on_remote_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data);
void on_remote_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data);
gboolean on_local_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data);
gboolean on_remote_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data);

char* get_known_hosts_file_path(void);
gboolean is_fingerprint_known(const char *host, int port, unsigned char *hash, size_t hlen);
gboolean verify_ssh_fingerprint(ssh_session session, const char *host, int port);
void save_fingerprint(const char *host, int port, unsigned char *hash, size_t hlen);

ConflictResponse show_conflict_dialog(const char *filename, const char *local_size, const char *local_date, const char *remote_size, const char *remote_date);
ConflictResponse show_directory_conflict_dialog(const char *dirname);

void format_file_size(char *buffer, size_t size, uint64_t bytes);
void format_file_date(char *buffer, size_t size, time_t mtime);

#endif
