import os
import re
import sys
import subprocess
import socket
import struct
import argparse

#Why is "set_toa_tcp_bs"? bs = beichen & skay
bpf_function_name = 'set_toa_tcp_bs'


bpf_content = b'\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xf7\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x40\x00\x09\x00\x01\x00\xbf\x16\x00\x00\x00\x00\x00\x00\x18\x07\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x61\x61\x00\x00\x00\x00\x00\x00\xbf\x12\x00\x00\x00\x00\x00\x00\x07\x02\x00\x00\xfd\xff\xff\xff\xb7\x03\x00\x00\x02\x00\x00\x00\x2d\x23\x22\x00\x00\x00\x00\x00\x15\x01\x26\x00\x0e\x00\x00\x00\x15\x01\x01\x00\x0f\x00\x00\x00\x05\x00\x31\x00\x00\x00\x00\x00\x18\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x71\x12\x00\x00\x00\x00\x00\x00\x71\x13\x06\x00\x00\x00\x00\x00\x67\x03\x00\x00\x08\x00\x00\x00\x71\x14\x05\x00\x00\x00\x00\x00\x4f\x43\x00\x00\x00\x00\x00\x00\x73\x2a\xf8\xff\x00\x00\x00\x00\xdc\x03\x00\x00\x10\x00\x00\x00\x6b\x3a\xfa\xff\x00\x00\x00\x00\x71\x12\x02\x00\x00\x00\x00\x00\x67\x02\x00\x00\x08\x00\x00\x00\x71\x13\x01\x00\x00\x00\x00\x00\x4f\x32\x00\x00\x00\x00\x00\x00\x71\x13\x03\x00\x00\x00\x00\x00\x67\x03\x00\x00\x10\x00\x00\x00\x71\x11\x04\x00\x00\x00\x00\x00\x67\x01\x00\x00\x18\x00\x00\x00\x4f\x31\x00\x00\x00\x00\x00\x00\x4f\x21\x00\x00\x00\x00\x00\x00\xdc\x01\x00\x00\x20\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\xb7\x01\x00\x00\x08\x00\x00\x00\x73\x1a\xf9\xff\x00\x00\x00\x00\xbf\xa2\x00\x00\x00\x00\x00\x00\x07\x02\x00\x00\xf8\xff\xff\xff\xbf\x61\x00\x00\x00\x00\x00\x00\xb7\x03\x00\x00\x08\x00\x00\x00\xb7\x04\x00\x00\x00\x00\x00\x00\x85\x00\x00\x00\x8f\x00\x00\x00\x05\x00\x12\x00\x00\x00\x00\x00\x61\x62\x54\x00\x00\x00\x00\x00\x47\x02\x00\x00\x40\x00\x00\x00\xbf\x61\x00\x00\x00\x00\x00\x00\x85\x00\x00\x00\x3b\x00\x00\x00\x05\x00\x0d\x00\x00\x00\x00\x00\x61\x61\x08\x00\x00\x00\x00\x00\x07\x01\x00\x00\x08\x00\x00\x00\x67\x01\x00\x00\x20\x00\x00\x00\x77\x01\x00\x00\x20\x00\x00\x00\xb7\x07\x00\x00\x01\x00\x00\x00\xb7\x02\x00\x00\x29\x00\x00\x00\x2d\x12\x01\x00\x00\x00\x00\x00\xb7\x07\x00\x00\x00\x00\x00\x00\x67\x07\x00\x00\x03\x00\x00\x00\xbf\x61\x00\x00\x00\x00\x00\x00\xbf\x72\x00\x00\x00\x00\x00\x00\xb7\x03\x00\x00\x00\x00\x00\x00\x85\x00\x00\x00\x90\x00\x00\x00\x63\x76\x04\x00\x00\x00\x00\x00\xb7\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00\xfe\x08\x08\x08\x08\x22\x05\x47\x50\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x45\x00\x00\x00\x04\x00\xf1\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x81\x00\x00\x00\x00\x00\x03\x00\x50\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7a\x00\x00\x00\x00\x00\x03\x00\x78\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6c\x00\x00\x00\x00\x00\x03\x00\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00\x03\x00\xe0\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x73\x00\x00\x00\x00\x00\x03\x00\xb8\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x12\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x01\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x11\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x3c\x00\x00\x00\x11\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x08\x00\x00\x00\x07\x08\x09\x00\x2e\x74\x65\x78\x74\x00\x2e\x72\x65\x6c\x73\x6f\x63\x6b\x6f\x70\x73\x00\x74\x6f\x61\x5f\x6f\x70\x74\x69\x6f\x6e\x73\x00\x73\x65\x74\x5f\x74\x6f\x61\x5f\x74\x63\x70\x5f\x62\x73\x00\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\x00\x5f\x6c\x69\x63\x65\x6e\x73\x65\x00\x74\x63\x70\x2d\x72\x74\x6f\x2e\x63\x00\x2e\x73\x74\x72\x74\x61\x62\x00\x2e\x73\x79\x6d\x74\x61\x62\x00\x2e\x64\x61\x74\x61\x00\x4c\x42\x42\x30\x5f\x38\x00\x4c\x42\x42\x30\x5f\x37\x00\x4c\x42\x42\x30\x5f\x36\x00\x4c\x42\x42\x30\x5f\x34\x00\x4c\x42\x42\x30\x5f\x33\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4b\x03\x00\x00\x00\x00\x00\x00\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\xf8\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x09\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x03\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x5f\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38\x02\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3d\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3f\x02\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x00\x00\x00\x03\x4c\xff\x6f\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x57\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x02\x00\x00\x00\x00\x00\x00\xf0\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x07\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00'


class UserOption:
    def __init__(self, toa_kind, toa_tcp_host, toa_tcp_port):
        self.toa_kind = toa_kind
        self.toa_tcp_host = toa_tcp_host
        self.toa_tcp_port = toa_tcp_port

        if type(self.toa_tcp_host) == str:
            packed_ip = socket.inet_aton(self.toa_tcp_host)
            self.toa_tcp_host = struct.unpack('!I', packed_ip)[0]

    def pack(self):
        return struct.pack('=B I H', self.toa_kind, self.toa_tcp_host, self.toa_tcp_port)

def get_current_cgroup():
    if os.path.exists('/sys/fs/cgroup/unified/'):
        return '/sys/fs/cgroup/unified/'

    with open('/proc/self/cgroup', 'r') as file:
        lines = file.readlines()

    cgroup_info = []
    for line in lines:
        cgroup_info = line.strip().split(':')

    return '/sys/fs/cgroup/' + cgroup_info[2][0:cgroup_info[2].index('/')]

def execute_command(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)

def get_my_sock_ops_id():
    ret = execute_command('bpftool prog show')
    pattern = r'(\d+): sock_ops\s+name\s+set_toa_tcp_bs'
    matches = re.search(pattern, ret)
    if matches:
        return matches.group(1)   
    return -1

def detach_bpf(cgroup):
    prog_id = get_my_sock_ops_id()
    if prog_id == -1:
        print('bpf prog not load')
        return
    ret = os.system(f'bpftool cgroup detach {cgroup} sock_ops id {prog_id}')
    os.remove(f'/sys/fs/bpf/{bpf_function_name}')
    if ret == 0:
        print("[*] detach sucess")
    else:
        print("[!] detach fail")    

def attach_bpf(bpf_content_bytes,cgroup):
    bpf_file = open(f'{bpf_function_name}.o','wb')
    bpf_file.write(bpf_content_bytes)
    bpf_file.close()
    os.system(f'bpftool prog load {bpf_file.name} /sys/fs/bpf/{bpf_function_name}')
    prog_id = get_my_sock_ops_id()
    os.remove(bpf_file.name)
    if prog_id == -1:
        print('[!] load bpf fail')
        return
    ret = os.system(f'bpftool cgroup attach {cgroup} sock_ops id {prog_id}')

    if ret == 0:
        print('[*] attach success')
    else:
        print('[!] attach fail')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process arguments.')

    # 参数定义
    parser.add_argument('method', choices=['attach', 'detach'],
                        help='Method to use: attach or detach')
    parser.add_argument('--toa_ip', required=False, default='8.8.8.8',
                        help='TOA IP address  Fake Address')
    parser.add_argument('--toa_port', required=False, type=int, default=80,
                        help='TOA port Fake Port')
    parser.add_argument('--toa_kind', required=False, type=int, default=254,
                        help='TOA kind (0-255)')
    parser.add_argument('--cgroup', required=False, type=str, default=None,
                        help='cgroup')
    
    if len(sys.argv) == 1:
        print("""
Usage:
    python3 toa.py attach --toa_ip 8.8.8.8
    python3 toa.py attach --toa_ip 8.8.8.8  --toa_port 80
    python3 toa.py attach --toa_ip 8.8.8.8  --toa_port 80 --toa_kind 254
    python3 toa.py detach
""")

    args = parser.parse_args()

    cgroup = args.cgroup

    if cgroup is None:
        cgroup = get_current_cgroup()
    bpf_id = get_my_sock_ops_id()
    print(f'[*] cgroup: {cgroup}')
    
    if args.method == 'attach':

        if bpf_id != -1:
            detach_bpf(cgroup)

        defaultUserOption = UserOption(254,'8.8.8.8',1314)
        defaultUserOptionBytes = defaultUserOption.pack()
        bpfStructStartIndex = bpf_content.find(defaultUserOptionBytes)
        if bpfStructStartIndex == -1:
            print('[!] bad bpf')
            sys.exit(0)
        else:
          new_bpf_content = bytearray(bpf_content)
          userOption = UserOption(args.toa_kind,args.toa_ip,args.toa_port)
          userOptionBytes = userOption.pack()
          for i in range(len(userOptionBytes)):
              new_bpf_content[bpfStructStartIndex + i] = userOptionBytes[i]
          new_bpf_content = bytes(new_bpf_content)
          attach_bpf(new_bpf_content,cgroup)   

    elif args.method == 'detach':
        detach_bpf(cgroup)
