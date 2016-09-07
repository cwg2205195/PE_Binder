#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<winnt.h>
// ===========This program is running for 32 bits programs , not for 64 bits !==============
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
	if(NT_head.FileHeader.Machine==0x8664)	//don't play with 64 bits PE file
	{
		printf("I need PE 32 not 64bits \n");
		exit(0);
	}
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
IMAGE_SECTION_HEADER* get_last_section(FILE *fp)
{
	IMAGE_DOS_HEADER DOS_head;// dos head
	IMAGE_NT_HEADERS32 NT_head;//  NT head
	IMAGE_SECTION_HEADER *section;
	int section_num;
	char buf[8],tmp;
//--------------------read DOS & NT & Section HEADERS ------------------------------

	rewind(fp);
	fread(&DOS_head,sizeof(IMAGE_DOS_HEADER),1,fp);
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);
	section_num=NT_head.FileHeader.NumberOfSections;		//record the number of sections 
	section=(IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	fseek(fp,(section_num-1)*sizeof(IMAGE_SECTION_HEADER),SEEK_CUR);	//go to the last section ?
	fread(section,sizeof(IMAGE_SECTION_HEADER),1,fp);	//get the last section's information

	//----------------debug----------------
/*	for(i=0;i<8;i++)
		buf[i]=section->Name[i];
		buf[7]=0;*/
//	printf("\ndebug  section name = %s\nvirtualAdd=%08X\nnumber of section %d \n",buf,section->VirtualAddress,NT_head.FileHeader.NumberOfSections);
	return section;
}
BOOL new_section_inf(FILE *fp,IMAGE_SECTION_HEADER * last_section,PE pe,int ori_file_size)		//adding a new section information in target file
{						//fp is the FILE pointer of target file , last_section is the ..of target file 
						//pe is the PE structure of the patch file 
	IMAGE_DOS_HEADER DOS_head;// dos head
	IMAGE_NT_HEADERS32 NT_head;//  NT head
	IMAGE_SECTION_HEADER *section,section_buf;
	int offset,section_num,i,j,section_align,new_image_size=0;
	char buf[]=".txet",tmp;
//--------------------Change the original NT_HEADER------------------------------

	rewind(fp);
	fread(&DOS_head,sizeof(IMAGE_DOS_HEADER),1,fp);
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);
	section_num=NT_head.FileHeader.NumberOfSections;
	NT_head.FileHeader.NumberOfSections++;					//********adding another section********
	section=(IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	memset(section,0,sizeof(IMAGE_SECTION_HEADER));
	section_align=NT_head.OptionalHeader.SectionAlignment;	//get section alignment
	while(pe.Size>section_align)			//calculating the virtual size of the patch file's code
	{
		new_image_size++;
		pe.Size-=section_align;
	}
	new_image_size++;
	new_image_size*=section_align;							//********the additional image size********
	NT_head.OptionalHeader.SizeOfImage+=new_image_size;		//*********the new image size*********
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);					//go back to PE
	fwrite(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);		//*********modify the NT_header********
//--------------------creating new section information------------------------

	for(i=0;i<sizeof(buf);i++)
		section->Name[i]=buf[i];			//*********new section name**********
	new_image_size=0;					//ree use the variable 
	while(last_section->Misc.VirtualSize>section_align)		//calculating the virtual size of the last section 
	{
		new_image_size++;
		last_section->Misc.VirtualSize-=section_align;
	}
	new_image_size++;
	new_image_size*=section_align;
//	printf("\nDEBUG the virtual size of the last section is %08X\n",new_image_size);
	section->VirtualAddress=last_section->VirtualAddress+new_image_size;		//********virtual address ********
	section->SizeOfRawData=pe.Size;			//********the raw size of patch file's code
	section->PointerToRawData=ori_file_size;//*********FOA of the patch code************
	section->Characteristics=IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_EXECUTE;	//********set section to RWE************
	section->Misc.VirtualSize=pe.Size;		//********the virtual size of the patch file ***********
//	printf("\nDEBUG the virtual Address new section is %08X\nthe raw data size is %08X\n",section->VirtualAddress,section->SizeOfRawData);
	fseek(fp,DOS_head.e_lfanew,SEEK_SET);
	fread(&NT_head,sizeof(IMAGE_NT_HEADERS32),1,fp);
	fseek(fp,section_num*sizeof(IMAGE_SECTION_HEADER),SEEK_CUR);
	fwrite(section,sizeof(IMAGE_SECTION_HEADER),1,fp);		//*********write the new section information*******
}
int main()
{
	FILE *patch,*target;	//patch is the pointer of patch.exe and target points to the target.exe ...it's obvious
	char path[30],path1[30];	//for storing the path of both file
	IMAGE_SECTION_HEADER *last_section;		//the last section information of the target file 
	PE pat,tar;
	char * buf;						//the buf points to the data that will be copied to target file 
	int offset,ep,jump_offset,target_org_size,tmp_offset;		//offset points to the end of new target file ,
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
	
//------------------------Read code from patch file & write code to target file-----------------------

	buf=(char*)malloc(pat.Size);		//allocating space for patch code
	fseek(patch,pat.FOA,SEEK_SET);		//go to patch file's code section
	fread(buf,pat.Size,1,patch);		//read codes to the buff
/*
	Sorry mate , I found out what was wrong ! I can not write the code directly at the end of the target file.
	I should write it at the end of the last section !
	BIG MISTAKE !!!
*/
	last_section=get_last_section(target);
	fseek(target,last_section->PointerToRawData+last_section->SizeOfRawData,SEEK_SET);//go to correct offset
	target_org_size=ftell(target);		//calculating the start FOA of the new code
	fwrite(buf,pat.Size,1,target);		//write codes to the target file
	tmp_offset=ftell(target);			//the end FOA of the code 
	
//-------------------------insert new section information-------------------

	new_section_inf(target,last_section,pat,target_org_size);
	
//-------------------------Calculating jump offset-------------------------

	fseek(target,tmp_offset,SEEK_SET);
	offset=ftell(target);				//next to the last byte of code....careful with 1 ....
	printf("wrote code @ %X \nended 	@ %X \n",target_org_size,offset);
	last_section=get_last_section(target);//get the new last section information 
	jump_offset=tar.EP-(last_section->VirtualAddress+last_section->Misc.VirtualSize);
	//printf("the final offset %08X\n",jump_offset);
	fseek(target,tmp_offset,SEEK_SET);
	fseek(target,-4,SEEK_CUR);			//go back 4 bytes ?
	fwrite(&jump_offset,4,1,target);	//modify the jump offset to the original Enrty Point

//-----------------------The End of the Process (Change EP)-----------------
	Change_EP(target,last_section->VirtualAddress);		//change EP of the target file
	//printf("\nNew EP(RVA) = %X\n",last_section->VirtualAddress);
	fclose(target);
	fclose(patch);
	return 0;
}
