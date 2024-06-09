#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mutator.h"

//////////////
//////////////
// Function to check if value is in the set
int isValueInSet(int *set, int size, int value) {
    for (int i = 0; i < size; i++) {
        if (set[i] == value) {
            return 1; // Value found
        }
    }
    return 0; // Value not found
}

// Function to add a value to the set
void addToSet(int **set, int *size, int value) {
    if (!isValueInSet(*set, *size, value)) {
        // Value not in set, add it
        *set = realloc(*set, (*size + 1) * sizeof(int));
        if (*set == NULL) {
            perror("Failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        (*set)[*size] = value;
        (*size)++;
    }
}
//////////////
//////////////

uint32_t fuzzing_engine(int fd, unsigned long addr, char *in_buf, int len) {

  signed int stage_cur, stage_max, stage_cur_byte, stage_cur_val;
  uint8_t i, j;
  uint8_t *stage_name = "init";
  uint8_t *stage_short = "init";
  uint8_t *out_buf;
  
  uint32_t  ret_val = 1;


  out_buf = malloc(len*sizeof(len));


 
 
  memcpy(out_buf, in_buf, len);

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 4;
  stage_name  = "bitflip 1/1";

  
  int *set = NULL;
  int setSize = 0;
  printf("%d\n", stage_max);
  printf("M1 ");
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 1;

    FLIP_BIT(out_buf, stage_cur);

	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */
    
    FLIP_BIT(out_buf, stage_cur);
  }
  printf("\n");

   
  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;



  printf("M2 ");
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 1;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }
  printf("\n");

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  printf("M3 ");
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }
  printf("\n");

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  printf("M4 ");
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */

    out_buf[stage_cur] ^= 0xFF;

  }
  printf("\n");

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

	printf("M5 ");
  for (i = 0; i < len - 1; i++) {

    stage_cur_byte = i;

    *(uint16_t*)(out_buf + i) ^= 0xFFFF;
    
	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */
    stage_cur++;

    *(uint16_t*)(out_buf + i) ^= 0xFFFF;


  }
  printf("\n");

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;


	printf("M6 ");
  for (i = 0; i < len - 3; i++) {

    stage_cur_byte = i;

    *(uint32_t*)(out_buf + i) ^= 0xFFFFFFFF;

	printf(": %s ", out_buf);
    /* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */

    stage_cur++;

    *(uint32_t*)(out_buf + i) ^= 0xFFFFFFFF;

  }
  printf("\n");
  
  
  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

	printf("M7 ");
  for (i = 0; i < len; i++) {

    uint8_t orig = out_buf[i];

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint8_t r = orig ^ (orig + j);

	printf(": %s ", out_buf);
	/* lseek(fd, addr, SEEK_SET); */
	/* if (write (fd, out_buf , len) == -1) { */
	/* 	printf("Error while writing\n"); */
	/* 	exit(1); */
	/* } */
      
      stage_max--;

      r =  orig ^ (orig - j);

      stage_max--;

      out_buf[i] = orig;

    }

  }
  printf("\n");


  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

 
	printf("M8 ");
  for (i = 0; i < len - 1; i++) {

    uint16_t orig = *(uint16_t*)(out_buf + i);


    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint16_t r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

	printf(": %s ", out_buf);
      /* lseek(fd, addr, SEEK_SET); */
  		/* if (write (fd, out_buf , len) == -1) { */
  	  /*  		printf("Error while writing\n"); */
  	  /* 		exit(1); */
  		/* } */

      stage_max--;
      
      stage_max--;

      
      *(uint16_t*)(out_buf + i) = orig;

    }

  }
  printf("\n");


  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;


	printf("M9 ");
  for (i = 0; i < len - 3; i++) {

    uint32_t orig = *(uint32_t*)(out_buf + i);


    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      uint32_t r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);
      
	printf(": %s ", out_buf);
      /* lseek(fd, addr, SEEK_SET); */
  		/* if (write (fd, out_buf , len) == -1) { */
  	  /*  		printf("Error while writing\n"); */
  	  /* 		exit(1); */
  		/* } */
      
      stage_max--;
      
      stage_max--;

      
      *(uint32_t*)(out_buf + i) = orig;
      	
    }

     
    if (i == len - 4) {

	printf("\n");
	return orig;
	}

    else

	continue;
  }
	printf("\n");

  return ret_val;

}



/*int main(){
	

	int start_val = 0x11111111;
	char *buf = malloc(4*sizeof(uint8_t));
	sprintf(buf, "%d", start_val);
	int len = strlen(buf);
	
	for(int i=0; i<5; i++){
		uint32_t retval = fuzzing_engine(buf, len);
		sprintf(buf, "%d", retval);
	}
}*/




 






  
