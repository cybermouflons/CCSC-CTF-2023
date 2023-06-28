.PHONY: all clean

TARGET = challenge

all: $(TARGET)

$(TARGET): challenge.rs
    @rustc -O --crate-type bin --edition=2018 -C link-args="-s" -o $(TARGET) $<

clean:
    @rm -f $(TARGET)
