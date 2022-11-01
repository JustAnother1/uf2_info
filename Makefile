TARGET  = uf2_info
OBJECTS = uf2_info.o
LIBS    = 


$(TARGET): $(OBJECTS)
	gcc $^ $(LIBS) -o $@

uf2_info.o: uf2_info.c
	gcc -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
