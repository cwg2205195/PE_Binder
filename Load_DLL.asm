;------------------------
; 万能补丁码
; 获取LoadLibraryA的函数地址并调用
; 
; 00000245      00001d7b      LoadLibraryA

; 戚利
; 2011.2.22
;------------------------
    .386
    .model flat,stdcall
    option casemap:none

include    windows.inc
include    user32.inc
includelib user32.lib
include    kernel32.inc
includelib kernel32.lib

;数据段
    .data

szText  db 'LoadLibrary的函数地址为： %08x',0
szOut   db '%08x',0dh,0ah,0
szBuffer db 256 dup(0)

;代码段
    .code

start:
   	mov eax,[esp]
	xor ax,ax
	jmp loc31 

loc21:
	sub eax,10000h	;减去一个页面的大小....it seems not like that ....
loc31:
	cmp dword ptr [eax],905A4Dh	;和MZ对比
	jne loc21
	mov ebx,eax		;ebx-> base of kernel32
   call loc0
   db 'LoadLibraryA',0  ;特征函数名
   db 'pa',0            ;动态链接库pa.dll
loc0:
   pop edx            ;edx中存放了特征函数名所在地址
   push edx
   push edx


loc2:   ;遍历导出表
   mov esi,dword ptr [ebx+3ch] ;esi->e_lfanew
   add esi,ebx ;ESI指向PE头
   mov esi,dword ptr [esi+78h]
   add esi,ebx ;ESI指向数据目录中的导出表
   mov edi,dword ptr [esi+20h] ;指向导出表的AddressOfNames
   add edi,ebx ;EDI为AddressOfNames数组起始位置
   mov ecx,dword ptr [esi+14h] ;指向导出表的NumberOfNames

   push esi
   xor eax,eax

loc3:
   push edi
   push ecx
   mov edi,dword ptr [edi]
   add edi,ebx  ;edi指向了第一个函数的字符串名起始
   mov esi,edx  ;esi指向了特征函数名起始
   xor ecx,ecx
   mov cl,0ch   ;特征函数名的长度
   repe cmpsb
   je loc4    ;找到特征函数，转移

   pop ecx
   pop edi
   add edi,4  ;edi移动到下一个函数名所在地址
   inc eax    ;eax为索引
   loop loc3
loc4:
   pop ecx
   pop edi
   pop esi ;ESI指向数据目录中的导出表   
   mov edi,dword ptr [esi+24h] ;指向导出表的Name索引
   add edi,ebx ;EDI为AddressOfNamesOrdinals数组起始位置

   ;计算eax处的值
   sal eax,1   ;eax中存放了指定索引距离数组的偏移
   add edi,eax
   mov ax,word ptr [edi]  ;又是一个索引
   mov edi,dword ptr [esi+1ch]  ;AddressOfFunctions
   add edi,ebx   
   
   sal eax,2
   add edi,eax
   mov eax,dword ptr [edi]
   add eax,ebx

   ;edx指向patch.dll
   ;加载dll，引发对补丁的调用
   pop edx
   add edx,0dh 
   push edx
   call eax
   ;跳转
   db 0E9h,0FFh,0FFh,0FFh,0FFh
   end start
