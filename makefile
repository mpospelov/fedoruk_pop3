CC = g++
SRC = POP3_client.c
NAME = POP3_client


.PHONY:	compile clean run

compile:
	$(CC) $(SRC) -o $(NAME) -lssl -lcrypto

clean:
	rm -f *~
	rm -f $(NAME)

run:
	./$(NAME)
