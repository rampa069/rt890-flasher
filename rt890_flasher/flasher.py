#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Radtel RT-890 Flasher Python Implementation

This utility allows flashing firmware to the Radtel RT-890 radio.
Based on the works of DualTachyon and JuantAldea's implementations.

Copyright 2025

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import time
import serial
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
BAUD_RATE = 115200
BAUD_RATE_SLOW = 19200
CHUNK_SIZE = 0x80  # 128 bytes
FULL_BINARY_SIZE = 60416  # 0xEC00 bytes
SPI_FLASH_SIZE = 4 * 1024 * 1024  # 4MB

# Command codes
CMD_READ = 0x52
CMD_ERASE = 0x39
CMD_FLASH = 0x57  # Firmware write command

class RT890Flasher:
    def __init__(self, port, verbose=False, slow_mode=False):
        """Initialize the flasher with the specified serial port."""
        self.verbose = verbose
        self.port_name = port
        self.port = None
        self.baud_rate = BAUD_RATE_SLOW if slow_mode else BAUD_RATE
        
        # Command constants
        self.ACK_RESPONSE = 0x06  # ACK response byte
        self.FLASH_MODE_RESPONSE = 0xFF
        self.CMD_ERASE_FLASH = CMD_ERASE
        self.CMD_READ_FLASH = CMD_READ
        self.CMD_WRITE_FLASH = CMD_FLASH
        self.WRITE_BLOCK_SIZE = CHUNK_SIZE
        self.MEMORY_SIZE = FULL_BINARY_SIZE
        
    def __enter__(self):
        """Open the serial port when entering context."""
        try:
            self.port = serial.Serial(
                port=self.port_name,
                baudrate=self.baud_rate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=2.0
            )
            if self.verbose:
                print(f"Opened port {self.port_name} at {self.baud_rate} baud")
            return self
        except serial.SerialException as e:
            print(f"Failed to open port {self.port_name}: {e}")
            raise
            
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the serial port when exiting context."""
        if self.port and self.port.is_open:
            self.port.close()
            if self.verbose:
                print(f"Closed port {self.port_name}")
    
    def setup_raw_port(self):
        """Configura el puerto serial en modo raw para comunicación directa."""
        # Guardar configuración actual
        old_timeout = self.port.timeout
        
        # Configurar opciones raw
        self.port.timeout = 1.0  # Tiempo de espera razonable
        
        # En sistemas POSIX (Linux/MacOS), podemos aplicar configuraciones raw adicionales
        if hasattr(self.port, 'fd'):
            import termios
            
            # Obtener atributos actuales
            attrs = termios.tcgetattr(self.port.fd)
            
            # Configurar modo raw
            # Deshabilitar procesamiento de caracteres especiales
            attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | 
                          termios.ISTRIP | termios.INLCR | termios.IGNCR |
                          termios.ICRNL | termios.IXON)
            # Deshabilitar procesamiento de salida
            attrs[1] &= ~termios.OPOST
            # Deshabilitar eco y señales
            attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | 
                          termios.ISIG | termios.IEXTEN)
            # Establecer tamaño de carácter a 8 bits
            attrs[2] &= ~termios.CSIZE
            attrs[2] |= termios.CS8
            
            # Aplicar configuración
            termios.tcsetattr(self.port.fd, termios.TCSANOW, attrs)
            
            if self.verbose:
                print("Puerto configurado en modo raw (configuración avanzada)")
        else:
            if self.verbose:
                print("Puerto configurado en modo básico (configuración limitada de raw)")
        
        return old_timeout
    
    def restore_normal_port(self):
        """Restaura el puerto serial a modo normal."""
        if hasattr(self.port, 'fd'):
            import termios
            
            # Obtener atributos actuales
            attrs = termios.tcgetattr(self.port.fd)
            
            # Configurar modo normal (no raw)
            attrs[0] |= (termios.IGNBRK | termios.BRKINT | termios.PARMRK | 
                         termios.ISTRIP | termios.INLCR | termios.IGNCR |
                         termios.ICRNL | termios.IXON)
            attrs[1] |= termios.OPOST
            attrs[3] |= (termios.ECHO | termios.ECHONL | termios.ICANON | 
                         termios.ISIG | termios.IEXTEN)
            
            # Aplicar configuración
            termios.tcsetattr(self.port.fd, termios.TCSANOW, attrs)
            
            if self.verbose:
                print("Puerto restaurado a modo normal")
    
    def append_checksum(self, data):
        """Calculate the checksum for command packets and append it."""
        checksum = sum(data) % 256
        data.append(checksum)
        return bytearray(data)
    
    def send_command(self, command, data=None):
        """Send a command to the radio and return the response."""
        if data is None:
            data = []
        
        # Prepare command packet
        packet = [command] + list(data)
        checksum = sum(packet) & 0xFF
        packet.append(checksum)
        
        # Print packet information in verbose mode
        if self.verbose:
            print("\nSending command:")
            print("Off | " + " ".join([f"0x{i:02X}" for i in range(min(16, len(packet)))]))
            print("=====|" + "=" * min(16, len(packet)) * 7)
            
            # Print packet data in rows of 16 bytes
            for i in range(0, len(packet), 16):
                row = packet[i:i+16]
                hex_data = ", ".join([f"0x{b:02X}" for b in row])
                print(f"0x{i:02X} | {hex_data}")
            print("=====|" + "=" * min(16, len(packet)) * 7)
        
        # Limpiar buffers antes de enviar
        self.port.reset_input_buffer()
        self.port.reset_output_buffer()
        
        # Send the command
        bytes_sent = self.port.write(bytes(packet))
        self.port.flush()
        
        if self.verbose:
            print(f"Sent {bytes_sent} bytes")
        
        # Read the response
        response = self.port.read(1)
        if not response:
            print("No response from radio. Is it in flash mode?")
            return None
        
        response_code = response[0]
        
        # Print response information in verbose mode
        if self.verbose:
            print("\nResponse:")
            print("Off | 0x00")
            print("=====|=====")
            print(f"0x00 | 0x{response_code:02X}")
            print("=====|=====")
            
        return response_code
    
    def read_radio_id(self):
        """Read the radio identification."""
        cmd = [CMD_READ, 0x00, 0x00, 0x00]
        response = self.send_command(cmd[0], cmd[1:])
        
        if response is None:
            return False
            
        # For RT-890, the response is usually 0xFF
        if response != 0xFF:
            print(f"Warning: Unexpected response from radio: 0x{response:02X}")
            
        return True
    
    def check_bootloader_mode(self):
        """Verificar si la radio está realmente en modo bootloader."""
        # Método 1: Intentar leer dirección 0 (típico de bootloader)
        cmd = [CMD_READ, 0x00, 0x00, 0x00]
        response = self.send_command(cmd[0], cmd[1:])
        
        if response is None:
            print("No response from radio.")
            return False
            
        # En modo bootloader, suele responder con 0xFF
        if response != 0xFF:
            print(f"Unexpected bootloader response: 0x{response:02X}")
            print("Radio may not be in bootloader mode.")
            return False
        
        # Método 2: Verificar LED o señal visual (esto requiere interacción del usuario)
        print("Please confirm the GREEN LED is ON (bootloader mode).")
        print("If the LED is not green, please restart the radio while holding both side keys.")
        confirmation = input("Is the GREEN LED on? (y/n): ").lower()
        
        if confirmation != 'y' and confirmation != 'yes':
            print("Bootloader mode not confirmed by user.")
            return False
        
        print("Bootloader mode confirmed.")
        return True
    
    def erase_flash(self):
        """Erase the flash memory before writing."""
        cmd = [CMD_ERASE, 0x00, 0x00, 0x55]
        response = self.send_command(cmd[0], cmd[1:])
        
        if response is None:
            return False
        
        # Para RT-890, aceptamos tanto 0x06 como 0xFF como respuestas válidas
        if response != 0x06 and response != 0xFF:
            print(f"Error: Flash erase failed with unexpected response: 0x{response:02X}")
            print("Expected either 0x06 or 0xFF")
            return False
            
        # Si llegamos aquí, consideramos que el borrado fue exitoso
        if self.verbose:
            print(f"Erase flash response: 0x{response:02X}")
        
        return True
    
    def cmd_write_flash(self, offset, bytes_128):
        """
        Write a 128-byte block to the radio's flash memory.
        
        Args:
            offset: Memory address offset to write to
            bytes_128: 128 bytes of data to write
            
        Returns:
            bool: True if write was successful, False otherwise
        """
        if len(bytes_128) != self.WRITE_BLOCK_SIZE:
            error_msg = (
                "Firmware chunk does not have the correct size. "
                f"Got 0x{len(bytes_128):02X} bytes, expected 0x{self.WRITE_BLOCK_SIZE:02X}."
            )
            print(f"FAILED: {error_msg}")
            return False

        # Prepare command following the format from the first code
        payload = [self.CMD_WRITE_FLASH, (offset >> 8) & 0xFF, (offset >> 0) & 0xFF]
        payload.extend(bytes_128)
        payload = self.append_checksum(payload)

        # Print debugging info if verbose
        if self.verbose:
            print(f"\nWriting at 0x{offset:04X}:")
            print(hexdump(payload, 32))

        # Clear buffers before sending
        self.port.reset_input_buffer()
        self.port.reset_output_buffer()

        # Send the command
        self.port.write(payload)
        self.port.flush()

        # Read response with appropriate timeout
        response = self.port.read(1)
        
        if not response:
            print(f"No response for write at offset 0x{offset:04X}")
            return False
        
        # Only accept 0x06 (ACK) as valid response
        if response[0] != self.ACK_RESPONSE:
            print(f"Error: Flash write failed at offset 0x{offset:04X} with response: 0x{response[0]:02X}")
            return False

        if self.verbose:
            print(f"Response:\n{hexdump(response, 32)}")

        # Small delay to ensure the write operation completes properly
        time.sleep(0.02)
        
        return True

    def flash_firmware(self, firmware_path):
        """Flash the firmware to the radio."""
        # Check if file exists
        if not os.path.isfile(firmware_path):
            print(f"Error: Firmware file '{firmware_path}' not found.")
            return False
        
        # Read the firmware file
        try:
            with open(firmware_path, 'rb') as f:
                firmware_data = f.read()
        except Exception as e:
            print(f"Error reading firmware file: {e}")
            return False
        
        firmware_size = len(firmware_data)
        print(f"Firmware size: {firmware_size} (0x{firmware_size:X}) bytes")
        
        # Configurar puerto en modo raw para todo el proceso
        old_timeout = self.setup_raw_port()
        
        # Check radio communication
        print("Checking radio communication...")
        if not self.read_radio_id():
            print("Failed to communicate with radio. Please make sure:")
            print("1. The radio is in flash mode (turn on while pressing both Side-Keys)")
            print("2. The programming cable is properly connected")
            print("3. You've selected the correct serial port")
            return False
        
        # Verify bootloader mode
        print("Verifying bootloader mode...")
        if not self.check_bootloader_mode():
            print("Radio is not in proper bootloader mode.")
            print("Please turn off the radio, then turn it on while holding BOTH side keys until the GREEN LED is on.")
            return False
        
        # Erase flash memory
        print("Erasing flash memory...")
        if not self.erase_flash():
            print("Flash erase failed. Aborting.")
            return False
        
        print("Flash erase successful. Starting firmware upload...")
        
        # IMPORTANTE: Esperar un tiempo después del borrado
        time.sleep(1.0)  # Esperar 1 segundo después del borrado
        
        # Calculate any necessary padding to align to block size
        fw_bytes = bytearray(firmware_data)
        last_chunk_size = len(fw_bytes) % self.WRITE_BLOCK_SIZE
        padding_to_add = (
            self.WRITE_BLOCK_SIZE - last_chunk_size if last_chunk_size else 0
        )

        if padding_to_add:
            print(f"Padding with {padding_to_add} zero bytes to align firmware to {self.WRITE_BLOCK_SIZE} bytes.")
            fw_bytes += bytearray([0x0] * padding_to_add)
            
        # Split firmware into chunks - using the method from the first code
        chunks = [
            [offset, fw_bytes[offset : offset + self.WRITE_BLOCK_SIZE]]
            for offset in range(0, len(fw_bytes), self.WRITE_BLOCK_SIZE)
        ]
        
        total_bytes = 0
        chunks_count = len(chunks)
        
        print(f"Total chunks to flash: {chunks_count}")
        
        for idx, chunk in enumerate(chunks):
            offset, data = chunk
            
            # Print progress every 10 chunks or for the first and last chunk
            if idx % 10 == 0 or idx == 0 or idx == chunks_count - 1:
                progress = (idx + 1) / chunks_count * 100
                print(f"Flashing at 0x{offset:04X} ({progress:.1f}% complete)")
            
            if self.verbose:
                print(f"\nBytes at 0x{offset:04X}:")
                print(hexdump(data, 32))
            
            # Use the cmd_write_flash method from the first code
            ok = self.cmd_write_flash(offset, data)
            
            if not ok:
                print(f"Failed to flash at address 0x{offset:04X}. Aborting.")
                return False
            
            total_bytes += len(data)
            
            # Small delay between blocks to ensure stability
            time.sleep(0.05)
        
        print(f"Flashed a total of {total_bytes} (0x{total_bytes:X}) bytes.")
        
        # Wait after flashing is complete
        time.sleep(1.0)
        
        print("All OK!")
        print("Firmware upload complete.")
        
        # Notify if firmware doesn't fill the whole memory
        if total_bytes != self.MEMORY_SIZE:
            note_str = (
                "Note: The firmware does not fill the whole memory. "
                "The radio will not restart automatically."
            )
            frame = "#" * len(note_str)
            print(f"\n{frame}\n{note_str}\n{frame}")
        
        return True
    
    def backup_spi(self, output_path):
        """Backup the SPI flash memory to a file."""
        print(f"Starting SPI flash backup ({SPI_FLASH_SIZE // 1024 // 1024}MB)...")
        
        # Check radio communication - importante: debe estar en modo NORMAL (no bootloader)
        if not self.read_radio_id():
            print("Failed to communicate with radio. Please make sure:")
            print("1. The radio is powered on normally (NOT in flash mode)")
            print("2. The programming cable is properly connected")
            print("3. You've selected the correct serial port")
            return False
        
        # Create the output directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        try:
            with open(output_path, 'wb') as f:
                # Configurar puerto en modo raw
                old_timeout = self.setup_raw_port()
                
                # Backup loop 
                for block_idx in range(32768):  # 32768 bloques de 128 bytes = 4MB
                    if block_idx % 256 == 0:
                        progress = block_idx / 32768 * 100
                        print(f"Reading at 0x{block_idx * 128:06X} ({progress:.1f}% complete)")
                    
                    # Limpiar buffers antes de cada comando
                    self.port.reset_input_buffer()
                    self.port.reset_output_buffer()
                    
                    # Comando 0x52 + 2 bytes dirección
                    cmd = [0x52, (block_idx >> 8) & 0xFF, block_idx & 0xFF]
                    checksum = sum(cmd) & 0xFF
                    cmd.append(checksum)
                    
                    if self.verbose:
                        print("\nSending command:")
                        print("Off | " + " ".join([f"0x{i:02X}" for i in range(len(cmd))]))
                        print("=====|" + "=" * len(cmd) * 7)
                        print(f"0x00 | {', '.join([f'0x{b:02X}' for b in cmd])}")
                        print("=====|" + "=" * len(cmd) * 7)
                    
                    # Enviar comando en modo raw (escritura directa)
                    bytes_sent = self.port.write(bytes(cmd))
                    self.port.flush()
                    
                    if self.verbose:
                        print(f"Sent {bytes_sent} bytes")
                    
                    # Pequeña pausa para asegurar procesamiento
                    time.sleep(0.02)
                    
                    # Leer primer byte para verificar error
                    response_header = self.port.read(1)
                    if not response_header:
                        print(f"No response from radio for block {block_idx}")
                        # Rellenar con ceros y continuar
                        f.write(bytes([0] * 128))
                        continue
                    
                    if self.verbose:
                        print("\nResponse:")
                        print("Off | 0x00")
                        print("=====|=====")
                        print(f"0x00 | 0x{response_header[0]:02X}")
                        print("=====|=====")
                    
                    if response_header[0] == 0xFF:
                        # En modo raw, podríamos recibir 0xFF como parte de una respuesta válida
                        # Intentar leer más bytes para confirmar si es un error o parte de los datos
                        additional_bytes = self.port.read(3)  # Leer 3 bytes más (cabecera)
                        
                        if not additional_bytes or len(additional_bytes) < 3:
                            print(f"Received error response or insufficient data for block {block_idx}")
                            # Escribir ceros y continuar
                            f.write(bytes([0] * 128))
                            continue
                        
                        # Ahora leer los 128 bytes de datos
                        data_block = self.port.read(128)
                        
                        if not data_block or len(data_block) < 128:
                            print(f"Incomplete data block: {len(data_block) if data_block else 0}/128 bytes")
                            # Rellenar con ceros si es necesario
                            if data_block:
                                data_block = data_block + bytes([0] * (128 - len(data_block)))
                            else:
                                data_block = bytes([0] * 128)
                        
                        # Leer el byte de checksum
                        checksum_byte = self.port.read(1)
                        
                        # Escribir datos en archivo
                        f.write(data_block)
                    else:
                        # Si el primer byte no es 0xFF, asumir datos directos
                        # Esto es menos probable según la implementación C#, pero es una alternativa
                        remaining_data = self.port.read(127)  # Leer 127 bytes restantes
                        
                        if not remaining_data or len(remaining_data) < 127:
                            print(f"Incomplete direct data: {len(remaining_data) if remaining_data else 0}/127 bytes")
                            # Rellenar con ceros
                            if remaining_data:
                                data_block = bytes([response_header[0]]) + remaining_data + bytes([0] * (127 - len(remaining_data)))
                            else:
                                data_block = bytes([response_header[0]]) + bytes([0] * 127)
                        else:
                            data_block = bytes([response_header[0]]) + remaining_data
                        
                        # Escribir en archivo
                        f.write(data_block)
                    
                    # Pequeña pausa entre bloques
                    time.sleep(0.01)
                
                # Restaurar configuración original
                self.port.timeout = old_timeout
                self.restore_normal_port()
                
                print(f"Backup process complete, saved to {output_path}")
                return True
                
        except Exception as e:
            print(f"Error during SPI backup: {e}")
            return False

    def restore_spi(self, backup_path):
        """Restore the SPI flash memory from a backup file."""
        print(f"Starting SPI flash restore ({SPI_FLASH_SIZE // 1024 // 1024}MB)...")
        
        # Check if file exists and has correct size
        if not os.path.isfile(backup_path):
            print(f"Error: Backup file '{backup_path}' not found.")
            return False
            
        try:
            with open(backup_path, 'rb') as f:
                backup_data = f.read()
        except Exception as e:
            print(f"Error reading backup file: {e}")
            return False
            
        if len(backup_data) != SPI_FLASH_SIZE:
            print(f"Error: Backup file is not exactly {SPI_FLASH_SIZE // 1024 // 1024}MB!")
            return False
        
        # Check radio communication - importante: debe estar en modo NORMAL (no bootloader)
        if not self.read_radio_id():
            print("Failed to communicate with radio. Please make sure:")
            print("1. The radio is powered on normally (NOT in flash mode)")
            print("2. The programming cable is properly connected")
            print("3. You've selected the correct serial port")
            return False
            
        # Verify radio is in normal mode (not bootloader)
        if self.check_bootloader_mode():
            print("RT-890 is not in normal mode!")
            print("Please power on the radio normally (NOT in flash mode).")
            return False
        
        try:
            # Configurar puerto en modo raw
            old_timeout = self.setup_raw_port()
            
            # Restore loop
            for offset in range(0, len(backup_data), self.WRITE_BLOCK_SIZE):
                # Print progress
                print(f"\rRestoring SPI at 0x{offset:06X}", end='', flush=True)
                
                # Get current chunk
                chunk = backup_data[offset:offset + self.WRITE_BLOCK_SIZE]
                
                # Prepare command
                cmd = [self.CMD_WRITE_FLASH, (offset >> 8) & 0xFF, offset & 0xFF]
                cmd.extend(chunk)
                cmd = self.append_checksum(cmd)
                
                # Clear buffers
                self.port.reset_input_buffer()
                self.port.reset_output_buffer()
                
                # Send command
                self.port.write(bytes(cmd))
                self.port.flush()
                
                # Read response
                response = self.port.read(1)
                if not response or response[0] != self.ACK_RESPONSE:
                    print(f"\nFailed to restore SPI at 0x{offset:06X}!")
                    return False
                
                # Small delay between blocks
                time.sleep(0.01)
            
            print("\nRestore complete. Power cycle your radio!")
            
            # Restore port settings
            self.port.timeout = old_timeout
            self.restore_normal_port()
            
            return True
            
        except Exception as e:
            print(f"\nUnexpected failure writing to SPI flash! Error: {e}")
            return False


def hexdump(byte_array, step):
    """
    Create a hexadecimal dump of the given byte array.
    
    Args:
        byte_array: The bytes to dump
        step: Number of bytes per line
        
    Returns:
        str: Formatted hexdump string
    """
    # Split into lines of 'step' bytes each
    dump = [byte_array[off : off + step] for off in range(0, len(byte_array), step)]
    
    # Format each byte as hex
    dump = [" ".join([f"{byte:02X}" for byte in _bytes]) for _bytes in dump]
    
    # Add offset at the start of each line
    dump = [f"{off * step:03X} | {_bytes}" for off, _bytes in enumerate(dump)]

    # Create header row
    header = f"Off | {' '.join([f'{i:02X}' for i in range(min(step, len(byte_array)))])}"

    # Create separator line
    separator = ["="] * len(dump[0] if dump else header)
    separator[4] = "|"
    separator = "".join(separator)

    return "{}\n{}\n{}\n{}".format(
        header, separator, "\n".join(dump), separator
    ) 