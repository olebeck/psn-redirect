ldr.w r0, [sp, #0x54] # load serverNameBuf from stack
mov r3, r0 # copy to another register

mov r2, #0x1234 # identifier to the hook
bl sceClibPrintf # call the hook
mov r1, r0 # store the returned length in r1
cmp r1, #0 # check if its < 0
ble.n patch_end # if its less than 0 no need to rewrite, skip the patch

ldr.w r0, [r11, #0xb0] # load template->allocator.alloc
bl call_alloc # allocate the returned length (r1) with the allocator in r0

mov r2, #0x1235 # identifier to the hook
bl sceClibPrintf # call the hook (r0 = buffer, r1 = length, r2 = identifier, r3 = serverNameBuf)
str.w r0, [sp, #0x54] # store the new buffer address in the serverNameBuf stack location

ldr.w r0, [r11, 0xb4] # load template->allocator.free
mov r1, r3 # load serverNameBuf to r1
bl call_dealloc # deallocate the old server name
b patch_end, # skip the to the end of the patch
