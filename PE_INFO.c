#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
// Vider le buffer clavier
int vider()
{
int a = 0;
while (a != '\n' && a != EOF)
{
a = getchar();
}
printf("Erreur de buffer !\n");
}


//--------------------------------------------------------------------------------------//

// Fonction similaire à scanf() pour éviter les buffers overflow
int xscanf(char *buffer, int ln)
{
char *p = NULL;

if (fgets(buffer, ln, stdin) != NULL)
{
p = strrchr(buffer, '\n');
if (p != NULL)
{
*p = 0;
}
else
{
vider();
return 0;
}
}
else
{
vider();
return 0;
}
return 1;
}

//----------------------------------------//

//fonction packer pour tester chaque fonction es ce que packer ou non selon une black_lise
void Packer(char *str,FILE *h)
{
int p1=1;

          //test withe black list
         if (strstr(str, "UPX") != NULL) p1=0;
         if (strstr(str, ".netshrink") != NULL) p1=0;
         if (strstr(str, "Armadillo Packer") != NULL) p1=0;
         if (strstr(str, "ASPack") != NULL) p1=0;
         if (strstr(str, "ASPR" )!= NULL) p1=0;
         if (strstr(str, "BoxedApp Packer") != NULL) p1=0;
         if (strstr(str, "CExe") != NULL) p1=0;
         if (strstr(str, "dotBundle") != NULL) p1=0;
         if (strstr(str, "Enigma Protector") != NULL) p1=0;
         if (strstr(str, "EXE Bundle") != NULL) p1=0;
         if (strstr(str, "EXE Stealth") != NULL) p1=0;
         if (strstr(str, "eXPressor") != NULL) p1=0;
         if (strstr(str, "kkrunchy src") != NULL) p1=0;
         if (strstr(str, "MEW") != NULL) p1=0;
         if (strstr(str, "MPRESS") != NULL) p1=0;
         if (strstr(str, "Obsidium") != NULL) p1=0;
         if (strstr(str, "PELock") != NULL) p1=0;
         if (strstr(str, "PESpin") != NULL) p1=0;
         if (strstr(str, "RLPack Basic") != NULL) p1=0;
         if (strstr(str, "Smart Packer Pro") != NULL) p1=0;
         if (strstr(str, "Themida") != NULL) p1=0;
         if (strstr(str, "VMProtect") != NULL) p1=0;
         if (strstr(str, "XComp/XPack") != NULL) p1=0;

//si p=0+++fonction packersinon non packer
if(p1==0)fprintf(h,"\n\n               ...... Fonction  packer - black-list ......\n\n");
else fprintf(h,"\n\n               .......     Fonction non packer     .......\n\n");

}
//---------------------------------------------//
//fonction pour recuperer les nom ou les ordinal des fonctoin importrt
void NonFonctions(char *Buffer, int iPos, DWORD dwRawData, DWORD dwThunk, DWORD dwAdresse, PIMAGE_THUNK_DATA ImgThunkData, FILE *f,FILE *h)
{
fseek(f, dwThunk, SEEK_SET);
fread(ImgThunkData, sizeof(IMAGE_THUNK_DATA), 1, f); // dwThunk mène vers une RVA
if (ImgThunkData->u1.AddressOfData != 0)
{
DWORD dwOffsetImport = dwRawData + (ImgThunkData->u1.AddressOfData - dwAdresse); // On convertit l'adresse en offset

if (ImgThunkData->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32) // Si la fonction est importée par ordinal, c'est à dire par sa 'position' dans la DLL...
{
sprintf(Buffer, " Une Fonction importer par ordinal 0x%04x ", ImgThunkData->u1.AddressOfData - IMAGE_ORDINAL_FLAG32);
}
else // Sinon on lit son nom
{
fseek(f, dwOffsetImport + sizeof(WORD), SEEK_SET);
fread(Buffer, sizeof(char), MAX_PATH-1, f);
strcat(Buffer, "()");
}

fprintf(h,"\t\t- %s\n", Buffer);
}

} // Fin



//---------------------------------------------//


//la fonction PEfichier pour tout information de LA PE
void PEfichier(char *strNomFichier)
{
//declaration des diff structure ,variable
IMAGE_NT_HEADERS peHead;
IMAGE_DOS_HEADER dosMZ;
IMAGE_IMPORT_DESCRIPTOR ImgImportDescriptor;
PIMAGE_OPTIONAL_HEADER ImgOptionalHeader;
IMAGE_SECTION_HEADER ImgSectionHeader;
IMAGE_THUNK_DATA ImgThunkData;
int iIndexSection = 0, iIndexImport = 0, iIndexFonction = 0;
DWORD dwNombreSections = 0;
DWORD dwAdresseSectionImport = 0;
DWORD dwAdresseImport = 0;
DWORD dwPointerToRawData = 0;
DWORD dwOffsetNomDll;
DWORD dwThunk;
DWORD dwOffsetFirstThunk;
char *strNomSection = NULL;
char strNomDll[MAX_PATH] = "";
char strNomFonction[MAX_PATH] = "";
int i;
//ouvrire le ficher à tester
FILE *f = fopen(strNomFichier, "rb");
//crée un fichier pour les resultat (PE_INFO.txt)
FILE *F = NULL;
F = fopen("PE_INFO.txt", "w+");
if (f != NULL)
{
// On lit l'en-tête DOS
fread(&dosMZ, sizeof(IMAGE_DOS_HEADER), 1, f);
// On se déplace à l'en-tête PE
fseek(f, dosMZ.e_lfanew, SEEK_SET);
//on la lit depuis l denier deplacemenet
fread(&peHead, sizeof(IMAGE_NT_HEADERS), 1, f);
//test les deux signature MZ et PE
fprintf(F,"\n+++++++++++++++++ PE validation +++++++++++++++++++++++\n\n");
if((dosMZ.e_magic== IMAGE_DOS_SIGNATURE) &&(peHead.Signature==IMAGE_NT_SIGNATURE))
{
fprintf(F,"   PE valide\n\n");
}
else
{
fprintf(F,"\n PE non valide...\n");
fclose(f);
getchar();
ExitProcess(0);
}
fprintf(F,"\n+++++++++++++++++++++ EntryPoint ++++++++++++++++++++++++++\n\n");
//afficher Address de EntryPoint
fprintf(F,"Address de EntryPoint est   :          0x%04x\n",peHead.OptionalHeader.AddressOfEntryPoint);
fprintf(F,"\n++++++++++++++++++++++ PE detail ++++++++++++++++++++++++\n");
//afficher diff details de PE
        fprintf(F,"\nMagicNumber:.................0x%04x",peHead.OptionalHeader.Magic);
        fprintf(F,"\nMajorLinkerVersion:..........0x%04x",peHead.OptionalHeader.MajorLinkerVersion);
        fprintf(F,"\nMinorLinkerVersion:..........0x%04x",peHead.OptionalHeader.MinorLinkerVersion);
        fprintf(F,"\nSizeOfCode:..................0x%04x",peHead.OptionalHeader.SizeOfCode);
        fprintf(F,"\nSizeOfInitializedData:.......0x%04x",peHead.OptionalHeader.SizeOfInitializedData);
        fprintf(F,"\nSizeOfUninitializedData:.....0x%04x",peHead.OptionalHeader.SizeOfUninitializedData);
        fprintf(F,"\nAddressOfEntryPoint :........0x%04x",peHead.OptionalHeader.AddressOfEntryPoint);
        fprintf(F,"\nBaseOfCode:..................0x%02x",peHead.OptionalHeader.BaseOfCode);
        fprintf(F,"\nBaseOfData:..................0x%04x",peHead.OptionalHeader.BaseOfData);
        fprintf(F,"\nImageBase:...................0x%04x",peHead.OptionalHeader.ImageBase);
        fprintf(F,"\nSectionAlignment:............0x%04x",peHead.OptionalHeader.SectionAlignment);
        fprintf(F,"\nFileAlignment:...............0x%04x",peHead.OptionalHeader.FileAlignment);
        fprintf(F,"\nMajorOperatingSystemVersion:.0x%04x",peHead.OptionalHeader.MajorOperatingSystemVersion);
        fprintf(F,"\nMinorOperatingSystemVersion:.0x%04x",peHead.OptionalHeader.MinorOperatingSystemVersion);
        fprintf(F,"\nMajorImageVersion:...........0x%04x",peHead.OptionalHeader.MajorImageVersion);
        fprintf(F,"\nMinorImageVersion:...........0x%04x",peHead.OptionalHeader.MinorImageVersion);
        fprintf(F,"\nMajorSubsystemVersion:.......0x%04x",peHead.OptionalHeader.MajorSubsystemVersion);
        fprintf(F,"\nMinorSubsystemVersion:.......0x%04x",peHead.OptionalHeader.MinorSubsystemVersion);
        fprintf(F,"\nWin32VersionValue:...........0x%04x",peHead.OptionalHeader.Win32VersionValue);
        fprintf(F,"\nSizeOfImage:.................0x%04x",peHead.OptionalHeader.SizeOfImage);
        fprintf(F,"\nSizeOfHeaders:...............0x%04x",peHead.OptionalHeader.SizeOfHeaders);
        fprintf(F,"\nCheckSum:....................0x%04x",peHead.OptionalHeader.CheckSum);
        fprintf(F,"\nSubsystem:...................0x%04x",peHead.OptionalHeader.Subsystem);
        fprintf(F,"\nDllCharacteristics:..........0x%04x",peHead.OptionalHeader.DllCharacteristics);
        fprintf(F,"\nSizeOfStackReserve:..........0x%04x",peHead.OptionalHeader.SizeOfStackReserve);
        fprintf(F,"\nSizeOfStackCommit:...........0x%04x",peHead.OptionalHeader.SizeOfStackCommit);
        fprintf(F,"\nSizeOfHeapReserve:...........0x%04x",peHead.OptionalHeader.SizeOfHeapReserve);
        fprintf(F,"\nSizeOfHeapCommit:............0x%04x",peHead.OptionalHeader.SizeOfHeapCommit);
        fprintf(F,"\nLoaderFlags:.................0x%04x",peHead.OptionalHeader.LoaderFlags);
        fprintf(F,"\nNumberOfRvaAndSizes:.........0x%04x\n",peHead.OptionalHeader.NumberOfRvaAndSizes);
fprintf(F,"\n+++++++++++++ LES Sections, leur details et le test packer pour chaque section ++++++++++++++++\n");
//recupere le nombre des section
dwNombreSections = peHead.FileHeader.NumberOfSections;
fprintf(F,"\n on a (%d) section  :\n", dwNombreSections);
ImgOptionalHeader = &peHead.OptionalHeader;
//recuperer l'addresse de la IAT
dwAdresseImport = (DWORD)(ImgOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
if (dwAdresseImport == 0)
{
fprintf(F,"\nIAT introuvable...\n");
fclose(f);
getchar();
ExitProcess(0);
}
// On va afficher toutes les sections trouvées
while (iIndexSection < dwNombreSections)
{
fread(&ImgSectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, f);
char *NomSection = ImgSectionHeader.Name;

fprintf(F,"\t\t# %s\n\t\t\t- V offset....: 0x%04x\n\t\t\t- R offset....: 0x%04x\n\t\t\t- V size......: 0x%04x\n\t\t\t- R size......: 0x%04x\n\t\t\t- Flag........: 0x%04x", ImgSectionHeader.Name, ImgSectionHeader.VirtualAddress, ImgSectionHeader.PointerToRawData, ImgSectionHeader.Misc,ImgSectionHeader.SizeOfRawData,ImgSectionHeader.Characteristics);
//appeller la fonction packer pour chaque section
Packer(NomSection,F);
// On récupère la section qui contient l'IAT.
// Il s'agit de la dernière section qui a son adresse inférieure à celle de l'IAT. (Adresse_Section_Dimport <= Adresse_IAT < Adresse_Section_Suivante)
// Ces données vont nous servir à convertir les RVAs en offset
if (ImgSectionHeader.VirtualAddress <= dwAdresseImport)
{
dwAdresseSectionImport = ImgSectionHeader.VirtualAddress;
dwPointerToRawData = ImgSectionHeader.PointerToRawData;
}
iIndexSection++;
}
int i=0;

fprintf(F,"\n+++++++++++++++++++++++++++++++ DLL Import ++++++++++++++++++++++++++++++\n\n");
fprintf(F,"Librairies et fonctions utilisees :\n\n");

fseek(f, dwPointerToRawData + (dwAdresseImport - dwAdresseSectionImport), SEEK_SET); // On convertit la RVA et on se place à l'offset de l'IAT
fread(&ImgImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, f);
while (ImgImportDescriptor.Name != 0) // On va lister les noms des DLLs utilisées
{
dwOffsetNomDll = dwPointerToRawData + (ImgImportDescriptor.Name - dwAdresseSectionImport); // On convertit en offset
fseek(f, dwOffsetNomDll, SEEK_SET);
fread(strNomDll, sizeof(char), MAX_PATH - 1, f);
fprintf(F,"\t# %s\n", strNomDll); // On affiche le nom que l'on vient de lire
iIndexFonction = 0;
// OriginalFirstThunk est similaire à FirstThunk sauf que ce dernier change lorsque le PE est chargé en mémoire.
// OriginalFirstThunk vaut parfois 0, notamment lorsque le PE a été compilé sous Borland. Dans ce cas, il faudra utiliser FirstThunk.

dwThunk = ImgImportDescriptor.OriginalFirstThunk;
if (dwThunk == 0)
{ dwThunk = ImgImportDescriptor.FirstThunk; }

dwOffsetFirstThunk = 0;
ImgThunkData.u1.AddressOfData = 1;

while (ImgThunkData.u1.AddressOfData != 0) // Tant qu'il y a des fonctions...
{

// On convertit la RVA en offset.
dwOffsetFirstThunk = dwPointerToRawData + (dwThunk - dwAdresseSectionImport) + sizeof(IMAGE_IMPORT_BY_NAME)*iIndexFonction;
//appeller la fonction NonFonctions pour recuperer les diffs fonction
NonFonctions(strNomFonction, iIndexFonction, dwPointerToRawData, dwOffsetFirstThunk, dwAdresseSectionImport, &ImgThunkData, f,F);

iIndexFonction++;
}

fprintf(F,"\n");

iIndexImport++;
fseek(f, dwPointerToRawData + (dwAdresseImport - dwAdresseSectionImport) + (sizeof(IMAGE_IMPORT_DESCRIPTOR)*iIndexImport), SEEK_SET);
fread(&ImgImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, f); // On lit l'IMAGE_IMPORT_DESCRIPTOR suivant
}
fclose(f);
} // Fin if(f != NULL)
else
{
fprintf(F,"\nImpossible d'ouvrir le fichier\n");
}

} // FIN


//---------------------------------------------------------------------//
int main(int argc, char *argv[])
{

char strChaine[MAX_PATH] = "";
//msg pour entrer le chemin de fichier a analysé
printf("Chemin du fichier a analyser : ");
//appeller la fonction xscanf pour recuperer le chemin de ficher
xscanf(strChaine, sizeof(strChaine));
//appeller la fonction PEfichier pour tester le ficher
PEfichier(strChaine);

getchar();
return 0;
}
