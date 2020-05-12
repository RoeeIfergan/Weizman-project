/*
        This Will be the Client side
*/

#include <stdlib.h>
#include <stdio.h>
#include <gtk/gtk.h>

//Client
#include "../../second.c"
#include "../../mbedtls/programs/test/roee_gcm_test.h"
typedef struct {
	GtkWidget *w_txtvw_main;            // Pointer to text view object
	GtkTextBuffer *textbuffer_main;     // Pointer to text buffer
	GtkTextBuffer *textbuffer_type;	    // Pointer to text buffer
} app_widgets;

int sock;
GtkBuilder      *builder;

//unsigned char key[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX";
//declaring the key
unsigned char key[128];
unsigned char * keyP = key;
//if key was entered successfully, keyValid = 0,if it's not valid than keyValid = -1
int keyValid = -1;
unsigned char keyCheck[] = "a293876b31f5d192e677dc860b6143298d9134bf74c2c475cbd4bee93a45501fd2233a7f399098b9f32fb55f2437e67ac7f7a264c0b86eb02463cca9cb5204f5a4d5d5cd38b21c9771162b571d98866a818959bc58539fcbe6e430ab7a4e931db2ec8dd02193b18193a11a29d0c39ff8b44f5903a4cd98cbf4099a214";

//valQ represents if user has requested to quit and server hasn't responded yet
int valQ = 0;


// called when window is closed
void on_window_main_destroy()
{
	//sending a quit msg  to server
        char text[] = "QUIT";
        unsigned char * msg = (unsigned char *) &text;
        sendToServer(msg, sock, key);

        //Decreases the reference count of object.
        // When its reference count drops to 0, the object is finalized (its memory is freed)
        g_object_unref(builder);

        //closing client socket
        closeClientSock(sock);

        //stopping gtk_main_iteration
        gtk_main_quit();
        exit(0);
}

void update_main_viewedit(app_widgets *app_wdgts, char bufInput[], char name[]) {
        //iter represents a place in the text buffer
        GtkTextIter iter;
        //iter at the end
        gtk_text_buffer_get_end_iter(app_wdgts->textbuffer_main, &iter);

        //inserting into main text buffer for displaying chat
        //inserting who wrote the msg
        gtk_text_buffer_insert(app_wdgts->textbuffer_main, &iter, name, -1);
        //inserting msg
        gtk_text_buffer_insert(app_wdgts->textbuffer_main, &iter, bufInput, -1);

        //updating iter at the end
        gtk_text_buffer_get_end_iter(app_wdgts->textbuffer_main, &iter);
        //inserting a new line
        gtk_text_buffer_insert(app_wdgts->textbuffer_main,&iter, "\n", -1);
}

void textview_type_send_msg(GtkButton *button, app_widgets *app_wdgts) {

	//iter represents a place in the text buffer
	//iter at the start
	GtkTextIter iterS;
	//iter at the end
	GtkTextIter iterE;
        //initializing start and end iter to represent start and end of typing text buffer - where user writes msgs to server
	gtk_text_buffer_get_start_iter(app_wdgts->textbuffer_type, &iterS);
        gtk_text_buffer_get_end_iter(app_wdgts->textbuffer_type, &iterE);

	//creating arrays of chars
	char text[500];
	char newText[500];

	//if key was entered successfully
	//copy '>' into text
	//add '>' to differ between user msgs and api msgs like the "QUIT" msg
	if(keyValid == 0) {
		strcpy((char * restrict) text, ">");
	}
	//get the text in the type buffer and copy it into newText
	//FALSE = Do not include hidden chars!
	strcpy((char * restrict) newText, gtk_text_buffer_get_text(app_wdgts->textbuffer_type, &iterS, &iterE, FALSE));
	//copy newText into text
	strncat((char * restrict) text, (char * restrict) newText,strlen(newText));

	//printing final text
	printf("Text: %s\n", text);

	//add text to the text buffer that displays the chat
	update_main_viewedit(app_wdgts, text, "Client#1: ");


	//clearing the text buffer for send msgs once updated the main text buffer for displaying chat
	gtk_text_buffer_set_text(app_wdgts->textbuffer_type,"",-1);

/*

	sending msg to server

*/
	//validating key generation

	//if key was entered successfully
	if(keyValid != 0) {

		const unsigned char* pass = text;
		int valKey = getKey(keyP, pass);

		if(valKey < 0) {
			printf("PROGRAM ERROR: password hashed did not hash successfully");
			exit(0);
		}

//		sprintf(*keyP, "%x", pass);
		printf("KEY: ");
		for(int i = 0; i < 128;i++)
                	printf("%x", key[i]);
	        printf("\n");

		int valid = 0;
		for(int i = 0; i < 128; i++) {
			if(strcmp(keyCheck[i], key[i]) != 0)
				valid = -1;
		}
		if(valid == 0) {
			keyValid++;
			update_main_viewedit(app_wdgts, "Verification successful!", "CONSOLE: ");
		}
		else {
			update_main_viewedit(app_wdgts, "Incorrect password, please retry", "CONSOLE: ");
		}
	}
	else {
		valQ = sendToServer((unsigned char *) &text, sock, key);
	}
	//validating if send worked
	if(valQ == 0)
		printf("Sent text\n");
	if(valQ == 1)
		on_window_main_destroy();

}


int main(int argc, char *argv[])
{
	//GtkBuilder      *builder;
	GtkWidget       *window;

	//creating a widgets from type app_widgets
	app_widgets     *widgets = g_slice_new(app_widgets);
	//GtkTextIter iter;

	//creating gtk_init
	gtk_init(&argc, &argv);
	printf("creating gtk_init successfully");

	//using gtk_builder to create the graphics for the gui using glade
	builder = gtk_builder_new_from_file("glade/window_main.glade");

	//binding the builder to the main container
	window = GTK_WIDGET(gtk_builder_get_object(builder, "window_main"));


	// Get pointers to widgets
	//pointer to the main text view where chat is shown
	widgets->w_txtvw_main = GTK_WIDGET(gtk_builder_get_object(builder, "txtview_main"));
	//pointer to main text buffer that displays the chat
	widgets->textbuffer_main = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "textbuffer_main"));
	//pointer to text buffer where user can type msgs for server
	widgets->textbuffer_type = GTK_TEXT_BUFFER(gtk_builder_get_object(builder, "textbuffer_type"));


	//connecting the widgets to signal to the builder
	gtk_builder_connect_signals(builder, widgets);

	//gtk_widget_show is called once done setting up widget settings
	gtk_widget_show(window);

	//start client side
	//connecting to sock
	sock = startClient();
	if(sock < 0) {
		printf("PROGRAM ERROR: Client did not launch!\n");
		exit(0);
	}
/*
	//validating key generation
	int valKey = getKey(keyP);
	//once password was entered successfully, check will be changed to 1
	int check = 0;

	if(valKey < 0) {
		printf("PROGRAM ERROR: password hashed did not hash successfully");
		exit(0);
	}
*/


	//currReceive is the status of the received data, if equal to 1 than data received,
	int currReceive = 0;

	//bufOutput is the data received
	char bufOutput[] = "";
	//pointer to bufOutput
	char  * bOP = bufOutput;

	//using a while loop for gtk_main_iteration
	//using gtk_main_iteration() instead of gtk_main() because i need to receive msgs while gui works - need to handle a few events
	while (1==1) {
		//runs 1 iteration of main loop
        	gtk_main_iteration();

		//checking if received data
		currReceive = receive(&bOP, sock, key, valQ);

		//currReceive = 1 if data was received
		if(currReceive == 1) {
			//printing msg in cmd
			printf("\nMessage: %s<\n", bOP);

			//updating the main buffer for viewing chat with the new msg received
			update_main_viewedit(widgets, bOP, "Server: ");
		}
		//if receiving failed, quit
		if(currReceive == -1) {
			on_window_main_destroy();
			return -1;
		}
	}


	//free widgets memory
	g_slice_free(app_widgets, widgets);

	return 0;
}
