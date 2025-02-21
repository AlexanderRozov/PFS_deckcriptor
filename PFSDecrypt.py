import os
import struct
import zlib
from pathlib import Path

PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52])
PNG_CHUNK_TYPES = ["PLTE", "IDAT", "bKGD", "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "iTXt", "pHYs", "sBIT", "sPLT", "sRGB", "sTER", "tEXt", "tIME", "tRNS", "zTXt"]
OGG_HEADER = bytes([79, 103, 103, 83, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

def parse_file_list(pfs_data):
    offset = 7  # 3 (pf8) + 4 (info_size)
    file_count = struct.unpack_from('<I', pfs_data, offset)[0]
    offset += 4
    
    files = []
    for _ in range(file_count):
        name_len = struct.unpack_from('<I', pfs_data, offset)[0]
        offset +=4
        
        name = pfs_data[offset:offset+name_len].decode('utf-8').replace('\\', '/')
        offset += name_len
        
        offset +=4  # skip zero
        
        file_offset = struct.unpack_from('<I', pfs_data, offset)[0]
        offset +=4
        
        file_size = struct.unpack_from('<I', pfs_data, offset)[0]
        offset +=4
        
        files.append({
            'name': name,
            'offset': file_offset,
            'size': file_size
        })
    
    return files

def guess_key_png(pfs_data, files):
    key = bytearray(20)
    png_files = [f for f in files if f['name'].lower().endswith('.png')]
    
    if not png_files:
        return None
    
    info = png_files[0]
    data = pfs_data[info['offset']: info['offset'] + info['size']]
    
    # First 16 bytes
    for i in range(16):
        key[i] = PNG_HEADER[i] ^ data[i]
    
    ihdr_encrypted = data[8:33]
    ihdr = bytearray()
    for i in range(25):
        ihdr.append(ihdr_encrypted[i] ^ key[(8 + i) % 20])
    
    crc_encrypted = data[29:33]
    crc = bytes([crc_encrypted[i] ^ key[(29 + i) % 20] for i in range(4)])
    expected_crc = int.from_bytes(crc, 'big')
    
    encrypted_width = data[16:20]
    tl = chr(data[40] ^ key[0])
    
    possible_chunk_types = [t for t in PNG_CHUNK_TYPES if t.endswith(tl)]
    
    for chunk_type in possible_chunk_types:
        key[17] = ord(chunk_type[0]) ^ data[37]
        key[18] = ord(chunk_type[1]) ^ data[38]
        key[19] = ord(chunk_type[2]) ^ data[39]
        
        for k16 in range(256):
            key[16] = k16
            
            # Decrypt width
            width = bytes([
                encrypted_width[0] ^ key[16],
                encrypted_width[1] ^ key[17],
                encrypted_width[2] ^ key[18],
                encrypted_width[3] ^ key[19],
            ])
            
            decrypted_data = bytearray()
            for i in range(13):
                decrypted_data.append(data[16 + i] ^ key[(16 + i) % 20])
            
            to_calc = b'IHDR' + decrypted_data
            calc_crc = zlib.crc32(to_calc) & 0xFFFFFFFF
            
            if calc_crc == expected_crc:
                return key
    
    return None

def guess_key_ogg(pfs_data, files):
    key = bytearray(20)
    ogg_files = [f for f in files if f['name'].lower().endswith('.ogg')]
    
    if not ogg_files:
        return None
    
    info = ogg_files[0]
    data = pfs_data[info['offset']: info['offset'] + info['size']]
    
    for i in range(20):
        key[i] = OGG_HEADER[i] ^ data[i]
    
    # Adjust key[14] and key[15]
    key[14] = (data[72] ^ key[12]) ^ data[14]
    key[15] = (data[73] ^ key[13]) ^ data[15]
    
    return key

def decrypt_file(data, key):
    return bytes([b ^ key[i % 20] for i, b in enumerate(data)])

def extract_files(pfs_data, files, key, output_dir):
    for file_info in files:
        file_data = pfs_data[file_info['offset']: file_info['offset'] + file_info['size']]
        decrypted = decrypt_file(file_data, key)
        
        output_path = Path(output_dir) / file_info['name']
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)

def main():
    pfs_path = './root.pfs.000'
    output_dir = './out'
    
    with open(pfs_path, 'rb') as f:
        pfs_data = f.read()
    
    files = parse_file_list(pfs_data)
    
    key = guess_key_png(pfs_data, files)
    if not key:
        key = guess_key_ogg(pfs_data, files)
    
    if not key:
        raise RuntimeError("Failed to guess encryption key")
    
    print("Encryption key:", key.hex())
    extract_files(pfs_data, files, key, output_dir)

if __name__ == '__main__':
    main()
