#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<winnt.h>
// ===========This program is running for 32 bits programs , not for 64 bits !=====================
typedef struct pe {
	int FOA,Size,Free_FOA,Free_Size,EP,VirtualAddr;
}PE;
BOOL check_PE(FILE *fp,char *path)
{
	int offset;
	IMAGE_DOS_HEADER DOS_head;// dos head
	IMAGE_NT_HEADERS32 NT_head;//  NT head
//	IMAGE_NT_HEADERS64 NT_head64;//64 bits head
	// -----------read DOS head-----------------
	fread(&DOS_head,sizeof(IMAGE_DOS_HEADER),1,fp);
	if(DOS_head.e_magic!=0x5a4d)	//?????MZ 
	{
		printf("%s\nDos head missing ! Or it is not a PE \n Exit .",path);
		exit(0);
	}
	//--------------Read NT head-------------------
	offset=DOS_head.e_lfanew;	//point to NT_HEADER32 or 64 ....
	fseek(fp,offset,SEEK_SET);
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);
	if(NT_head.Signature!=0x4550)	//PE 
	{
		printf("%s\nNot PE ! \n Exit .\n",path);
		exit(0);
	}
	rewind(fp);		//rolling back to beginning of the file 
	return 1;
}
void get_text(FILE *fp,PE &pe,int flag)
{
	IMAGE_DOS_HEADER DOS_head;// dos head
	IMAGE_NT_HEADERS32 NT_head;//  NT head
	IMAGE_SECTION_HEADER *sections;
	int offset,section_num,i,j;
	char buf[8],tmp;
//--------------------read DOS & NT & Section HEADERS ------------------------------
	rewind(fp);
	fread(&DOS_head,sizeof(IMAGE_DOS_HEADER),1,fp);
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);
	pe.EP=NT_head.OptionalHeader.AddressOfEntryPoint;		//record the Entry Point RVA
	section_num=NT_head.FileHeader.NumberOfSections;		//record the number of sections 
	sections=(IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER)*section_num);
	fread(sections,sizeof(IMAGE_SECTION_HEADER),section_num,fp);
	for(i=0;i<section_num;i++)
	{
		for(j=0;j<8;j++)
			buf[j]=(sections+i)->Name[j];
		if(!strcmp(buf,".text"))
					break;
	}
	sections+=i;
/*	for(i=0;i<8;i++)
		printf("%c",sections->Name[i]);*/
	pe.FOA=sections->PointerToRawData;
	pe.Size=sections->SizeOfRawData;
	pe.Free_Size=sections->SizeOfRawData-sections->Misc.VirtualSize;
	pe.Free_FOA=sections->SizeOfRawData+sections->PointerToRawData-pe.Free_Size;
	pe.VirtualAddr=sections->VirtualAddress;
//----------------calculating the 0 bytes in the file (more reliable but space is small ...)--------------------
	if(1==flag)			//it's the patch file
	{	
		j=pe.FOA+pe.Size-1;			//j serves as a pointer 
		fseek(fp,j,SEEK_SET);		//point to the end of the .text section 
		i=0;
		tmp=fgetc(fp);
		while(!tmp)					//searching for non 0 byte 
		{
			i++;					//i is the free size ,the same as 0 byte
			j--;					//j is the pointer to the free space 
			fseek(fp,j,SEEK_SET);	//using j to adjust the FILE pointer
			tmp=fgetc(fp);
		}
		pe.Size=pe.Size-i;
		pe.Free_Size=i-1;
		pe.Free_FOA=j+1;
	}
//---------------------debug output ----------------------
//	printf("\nEP=%08X FOA=%08X  Size=%08X Free_FOA=%08X Free_Size=%08X\n",pe.EP,pe.FOA,pe.Size,pe.Free_FOA,pe.Free_Size);
}
int RVA_TO_FOA(PE pe,int ep)	//convert RVA to FOA ...it's obvious
{
	return ep-pe.VirtualAddr+pe.FOA;
}
int FOA_TO_RVA(PE pe)			//convert FOA to RVA ...it's obvious
{
	return pe.Free_FOA-pe.FOA+pe.VirtualAddr;
}
void Change_EP(FILE *fp,int new_ep)
{
	IMAGE_DOS_HEADER DOS_head;// dos head
	IMAGE_NT_HEADERS32 NT_head;//  NT head
	rewind(fp);
	fread(&DOS_head,sizeof(IMAGE_DOS_HEADER),1,fp);			//read dos header
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);					//Go to PE
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);		//readd pe header
	NT_head.OptionalHeader.AddressOfEntryPoint=new_ep;		//change Entry Point
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);					//Go to PE
	fwrite(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);		//write back
}
int main()
{
	FILE *patch,*target;	//patch is the pointer of patch.exe and target points to the target.exe ...it's obvious
	char path[30],path1[30];	//for storing the path of both file
	PE pat,tar;
	char * buf;						//the buf points to the data that will be copied to target file 
	int offset,ep,jump_offset;		//offset points to the end of new target file ,
									// ep is the Entry Point of the original target file
									//jump_offset adjust the last four bytes of the target code 
//------------------------Open file to process ---------------------------
	printf("patch file path :");
	scanf("%s",path);
	printf("target file path :");
	scanf("%s",path1);
	if((patch=fopen(path,"r"))==NULL)
	{
		printf("failed to open %s !\n Exit !\n",path);
		return 1;
	}
	if((target=fopen(path1,"r+"))==NULL)
	{
		printf("failed to open %s !\n Exit !\n",path1);
		fclose(patch);		//closing the patch file 
		return 1;
	}

//------------------------Checking for PE file -----------------------

	check_PE(patch,path);
	check_PE(target,path1);

//------------------------gaining information about .text section-----------------------	
	get_text(patch,pat,1);
	get_text(target,tar,0);
//------------------------key comparison---------------------------
	if(pat.Size>tar.Free_Size)
	{
		printf("Can not bind file %s\nThe target %s has not enough space for it \n Exit !\n",path,path1);
		return 1;
	}
//------------------------Procede mission -----------------------
	buf=(char*)malloc(pat.Size);		//allocating space for patch code
	fseek(patch,pat.FOA,SEEK_SET);		//go to patch file's code section
	fread(buf,pat.Size,1,patch);		//read codes to the buff
	fseek(target,tar.Free_FOA,SEEK_SET);//go to target file's free space
	fwrite(buf,pat.Size,1,target);		//write codes to the target file
	offset=ftell(target);				//next to the last byte of code....careful with 1 ....
	printf("\n\nwrote code @ %X \nended 	@ %X \n",tar.Free_FOA,offset);
//	printf("test EP=(RVA)%X = (FOA)%X",tar.EP,RVA_TO_FOA(tar,tar.EP));
	ep=RVA_TO_FOA(tar,tar.EP);			//get the raw offset of the target PE .
	jump_offset=ep-offset;				//calculating the adjustment offset
//	printf("the final offset %X\n",jump_offset);
	fseek(target,-4,SEEK_CUR);			//go back 4 bytes ?
	fwrite(&jump_offset,4,1,target);	//modify the jump offset to the correct Enrty Point
//-----------------------The End of the Process (Change EP)-----------------
	jump_offset=FOA_TO_RVA(tar);		//the new Entry Point of the target file 
	Change_EP(target,jump_offset);		//change EP of the target file
	printf("\nNew EP(RVA) = %X\n",jump_offset);
	fclose(target);
	fclose(patch);
	return 0;
}
