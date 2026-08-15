#define CUHM_IMPLEMENTATION
#include "./vendor/cuhm/cuhm.h"

#include <gtk/gtk.h>

#define MAX_PATH_LEN 100
#define MAX_HOST_LEN 100

void destroy(GtkWidget* widget, gpointer data){

  gtk_main_quit();

}

void on_URL_entry(GtkEntry* entry, gpointer data){

  GtkWidget *text_view = GTK_WIDGET(data);
  GtkTextBuffer *gtk_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));


  const gchar* url = gtk_entry_get_text(entry);
  char* file_path = "/tmp/gem_alert.gmi";

  if (strstr(url,"gemini://") != NULL) url += strlen("gemini://");
  
  char hostname[MAX_HOST_LEN]; memset(&hostname, 0, sizeof(hostname));
  char path[MAX_PATH_LEN]; memset(&path, 0, sizeof(path));
  StringView le_URL = {0};
  le_URL.data = url;
  le_URL.count = strlen(url);

  StringView sv_hostname = sv_chop_by_delim(&le_URL, '/');
  sv_to_cstring(hostname,&sv_hostname);
  if (strstr(url,"/")){
    sv_to_cstring(path,&le_URL);
  }else{
    strcpy(path,"");
  }


  SslCtxSock le_sockets = CUHM_ConnectToServiceSSL(hostname,"1965");
  if (le_sockets.sockfd == 0) {

    char message[100];
    strcpy(message, "Cannot reach the ");strcat(message, hostname);strcat(message,"...");
    gchar* valid_message = g_utf8_make_valid(message,strlen(message));
    gtk_text_buffer_set_text(gtk_buffer,message, -1);
    return;

  }
  HeaderData le_header = CUHM_RetrieveHeaderGemini(hostname,path,&le_sockets);
  if (le_header.code != 20){

    char message[100];
    strcpy(message, "Error: ");strcat(message, le_header.header.data);
    gchar* valid_message = g_utf8_make_valid(message,strlen(message));
    gtk_text_buffer_set_text(gtk_buffer,message, -1);
    return;

  }
  FILE* fp = fopen(file_path,"wb");
  CUHM_RetrieveFileGemini(&le_sockets, fp);
  fp = fopen(file_path,"r");
  fseek(fp, 0, SEEK_END);
  int filesize = ftell(fp);
  char *buffer = calloc(filesize + 1,sizeof(char));
  rewind(fp);
  fread(buffer, filesize, 1, fp);
  gchar* valid_buffer = g_utf8_make_valid(buffer,strlen(buffer));
  fclose(fp);
  free(buffer);

  gtk_text_buffer_set_text(gtk_buffer, valid_buffer, -1);

}

int main(int argc, char **argv){

  char *buffer = "enter URL";
  gchar* valid_buffer = g_utf8_make_valid(buffer,strlen(buffer));

  gtk_init(&argc,&argv);
  GtkWidget* window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  GtkWidget* scrolled_window = gtk_scrolled_window_new(NULL,NULL);
  gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);

  GtkWidget* vertical_box = gtk_box_new(GTK_ORIENTATION_VERTICAL,5);

  GtkWidget* url_entry = gtk_entry_new();
  gtk_entry_set_placeholder_text(GTK_ENTRY(url_entry),"Your gemini:// URL goes here...");
  gtk_box_pack_start(GTK_BOX(vertical_box),url_entry,FALSE,FALSE,0);

  GtkWidget *text_view = gtk_text_view_new();
  GtkTextBuffer *gtk_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
  gtk_text_buffer_set_text(gtk_buffer, valid_buffer, -1);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
  gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);
  gtk_box_pack_start(GTK_BOX(vertical_box),scrolled_window,TRUE,TRUE,0);
  gtk_container_add(GTK_CONTAINER(window),vertical_box);

  g_signal_connect(window, "destroy", G_CALLBACK(destroy), NULL);
  g_signal_connect(url_entry,"activate",G_CALLBACK(on_URL_entry), text_view);

  gtk_widget_show_all(window);
  gtk_main();

  return 0;

}
