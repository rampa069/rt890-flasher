# RT-890 Flasher

A Python tool for flashing and backing up Radtel RT-890 firmware.

## Installation

```bash
pip install rt890-flasher
```

## Usage

### Flash Firmware

```bash
rt890-flash [OPTIONS] PORT FIRMWARE_FILE
```

Options:
- `-v, --verbose`: Enable verbose output with protocol debugging
- `-s, --slow`: Use slow baud rate (19200)
- `-d, --debug`: Enable extra debugging information
- `-l, --list`: List available serial ports

### Backup SPI eeprom

```bash
rt890-backup [OPTIONS] PORT OUTPUT_FILE
```

Options:
- `-v, --verbose`: Enable verbose output with protocol debugging
- `-s, --slow`: Use slow baud rate (19200)
- `-d, --debug`: Enable extra debugging information
- `-l, --list`: List available serial ports

### Restore SPI eeprom

```bash
rt890-restore [OPTIONS] PORT BACKUP_FILE
```

Options:
- `-v, --verbose`: Enable verbose output with protocol debugging
- `-s, --slow`: Use slow baud rate (19200)
- `-d, --debug`: Enable extra debugging information
- `-l, --list`: List available serial ports

## Examples

List available ports:
```bash
rt890-flash --list
# or
rt890-backup --list
# or
rt890-restore --list
```

Flash firmware:
```bash
rt890-flash /dev/ttyUSB0 firmware.bin
```

Backup SPI eeprom:
```bash
rt890-backup /dev/ttyUSB0 backup.bin
```

Restore SPI eeprom:
```bash
rt890-restore /dev/ttyUSB0 backup.bin
```

## License

Licensed under the Apache License, Version 2.0 
