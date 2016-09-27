/* Stats.c file */

/*
 *  file extractions
 *  record manipulations
 *
*/

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Config.h"
#include "Client.h"




void fileInitialize ( const char *fileName, config *inputSettings )
{

	char* file = malloc(sizeof(char)*200);
	long filesize;
	struct stat fileStatCode;
	file = strcpy(file,fileName);
	if(stat(file,&fileStatCode))
	{
	    	filesize = fileStatCode.st_size;
	    	if(filesize > MAX_FILE_SIZE)
	    	{
	    		LOG("Only Max size will be transfered",filesize);
	    	}


	    inputSettings->Extractor_file = fopen (file, "rb");
	    if ( (inputSettings->Extractor_file) == NULL )
        {
             LOG("could not find the file",1);
             LOG("Using Default",2);
		    return;
        }
	}
	else
		LOG("Could not stat file",1);
}

int fileBlockCopyToBuffer(char *readData,config *inputSettings)
{
	int rc;
	if(readData == NULL)
	{
		LOG("Could not find buffer",1);
		return -1;
	}
	if(!(feof(inputSettings->Extractor_file)))
    {
	    rc = fread( readData, 1, inputSettings->mBufLen,
    		    inputSettings->Extractor_file );
        if((rc < inputSettings->mBufLen)&& (!feof(inputSettings->Extractor_file)))
        {

        	LOG("fileBlockCopyToBuffer: Not all data was read",1);
        }
    }
    printf("%d\n",rc);
	return rc;
}


/*
 *Tests begin
 *Routines below are for testing purposes only
*/


void testprint_buffer(uint8_t *buffer, uint16_t bufferLen)
{
    int i;
    uint8_t *print_ptr = (uint8_t *)buffer;

    printf("%s: buf_len = %d, data = %p\n", __FUNCTION__, bufferLen, buffer);
    for (i = 0; i < (bufferLen); i++)
    {
        if ((i % 16) == 0)
        {
            printf("\n0x%04x   ", (print_ptr+1));
        }
        else if (i%4 == 0)
        {
            printf(" ");
        }
        printf("%02x ", *(print_ptr + i));
    }
    printf("\n\n");
}

int testBufferCopy(int sizecopy, const char* filefrom,const char* fileto,int bufLen)
{
	config *inputSettings;
	inputSettings = malloc(sizeof(config));
	memset((config *)inputSettings,0,sizeof(inputSettings));
	inputSettings->mBufLen = bufLen;
	char* buf = malloc(sizeof(char)*20);
	memset((char *)buf,0,sizeof(buf));
	fileInitialize(filefrom,inputSettings);
	printf("entered 3 \n");
	LOG("entered 3",1);
	do{
	    if(inputSettings->Extractor_file != NULL)
	    {
	    	fileBlockCopyToBuffer(buf,inputSettings);
	    }
        FILE* fd = fopen(fileto,"a");
	    fwrite(buf,1,sizecopy,fd);
        LOG("entered log",1);

	}while(!feof(inputSettings->Extractor_file));
	return 0;
}
