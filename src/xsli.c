/****************************************************************************
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <https://unlicense.org>
 ***************************************************************************/
/*---------------------------------------------------------------------------
    SLI Extractor

    Author  : White Guy That Don't Smile
    Date    : 2021/10/30, Saturday, October 30th; 0735 HOURS
    License : UnLicense | Public Domain

    This is a personal tool of mine that I lazily threw together
    as a facility for dumping SLI data from Nintendo's binaries,
    in addition to, using the data for analysis and rearranging
    Nintendo 64 ROMs back to their native endianness.
---------------------------------------------------------------------------*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>



#define EXT_SZP ".szp"  /* SLI Zip Partition */
#define EXT_SZS ".szs"  /* SLI Zip Stream */



/*---------------------------------------------------
## N64 Titles [incomplete] that use "MIO0" ##
[1997] AeroFighters Assault
[1999] Beetle Adventure Racing!
[1998] Body Harvest
[1998] F-1 World Grand Prix
[1999] F-1 World Grand Prix II
[1998] F-Zero X
[2000] Indy Racing 2000
[2000] Looney Tunes: Duck Dodgers Starring Daffy Duck
[1996] Mario Kart 64
[1996] Pilotwings 64
[1997] Star Fox 64
[1996] Super Mario 64
---------------------------------------------------*/
#define MIO 0x4D494F30



/*-----------------------------------------------------
## N64 Titles [incomplete] that use "CMPR", "SMSR00" ##
[1997] Yoshi's Story
-----------------------------------------------------*/
#define CMPR 0x434D5052
#define SMSR 0x534D5352



/*---------------------------------------------------------------------
## N64 Titles [incomplete] that use "Yay0" ##
[1998] 1080 Snowboarding
[2000] BattleZone: Rise of the Black Dogs
[1999] Bomberman 64: The Second Attack!
[2000] Disney's Donald Duck: Goin' "Qu@c|<ers?*!"
[2000] Fushigi no Dungeon: Fuurai no Shiren 2 - Oni Shuurai! Shiren Jou
[1998] Kiratto Kaiketsu! 64 Tanteidan
[1999] Neon Genesis Evangelion
[2000] Nushi Tsuri 64: Shiokaze Ninotte
[2000] Paper Mario
[1999] Parlor! Pro 64: Pachinko Jikki Simulation
[1999] Pokemon Stadium
[2000] Pokemon Stadium 2
[1999] Rayman 2: The Great Escape
[2000] Scooby-Doo! Classic Creep Capers
[1999] Shadowgate 64: Trials of the Four Towers
[1999] Tonic Trouble
[2000] Tsumi to Batsu: Hoshi no Keishousha
[1999] Zoor: Majuu Tsukai Densetsu

## Other Titles [incomplete] that contain "Yay0" data ##
[2001] [GCN] Luigi's Mansion
---------------------------------------------------------------------*/
#define Yay 0x59617930



/*------------------------------------------------------
## N64 Titles [incomplete] that use "Yaz0" ##
[2001] Animal Forest
[2000] The Legend of Zelda: Majora's Mask
[1998] The Legend of Zelda: Ocarina of Time

## Other Titles [incomplete] that contain "Yaz0" data ##
[2003] [GCN] Mario Kart: Double Dash!!
[2011] [3DS] Super Mario 3D Land
[2002] [GCN] Super Mario Sunshine
[2002] [GCN] The Legend of Zelda: The Wind Waker
[2006] [GCN] The Legend of Zelda: Twilight Princess
------------------------------------------------------*/
#define Yaz 0x59617A30



/*--------------------------------------------
Some N64 ROMS contain data using an SLI header
prefixed with "GZIP".
--------------------------------------------*/
#define GZIP 0x475A4950



/*-------------------------------------------------
FILENAME_MAX
 - [20 Character Game Name + 1 NULL Terminator]
 - [4 Character Game ID + 1 NULL Terminator]
 - [4 Character File Extension + 1 NULL Terminator]
-------------------------------------------------*/
#define PPATH_MAX (FILENAME_MAX - 21 - 5 - 5)



typedef unsigned char  u8;
typedef unsigned short u16;
#ifdef __x86_64__
typedef   signed int   i32;
typedef unsigned int   u32;
#else
typedef   signed long  i32;
typedef unsigned long  u32;
#endif



static u16 _swap16( u16 data )
{
  return (u16)(((data & 0x00FF) << 8) |
               ((data & 0xFF00) >> 8));
}

static u32 _swap32( u32 data )
{
  return (u32)(((u32)_swap16((u16)( data & 0x0000FFFF)) << 16) |
               ((u32)_swap16((u16)((data & 0xFFFF0000)  >> 16))));
}



static struct
{
  u32 toDecode    : 1;
  u32 useGameName : 1;
  u32 writeROM    : 1;
  u32 verbose     : 1;
}
options;



static u32 cleanUpOnError( FILE *SLI, FILE *DECODED,
                           char *dataEntry, char *decodedDest )
{
  if ( SLI != (FILE *)0 )
  {
    fclose( SLI );

    if ( dataEntry != (char *)0 )
    {
      remove( dataEntry );
    }
  }

  if ( DECODED != (FILE *)0 )
  {
    fclose( DECODED );

    if ( decodedDest != (char *)0 )
    {
      remove( decodedDest );
    }
  }

  if ( dataEntry != (char *)0 )
  {
    free( dataEntry );
    dataEntry = (char *)0;
  }

  if ( decodedDest != (char *)0 )
  {
    free( decodedDest );
    decodedDest = (char *)0;
  }

  return 0;
}



static void decbuf( const u8 *srcbuf, u8 **dst, const u32 position,
                    const u32 magic, const u32 sizeDecoded )
{
  u8 *dest;
  u8 *previous;
  u32 masks = 0;
  u32 flags = 0;
  /*--------------------------------------------------------------------
  Position for Polymorphic variables.
  For MIO0/SMSR00, a half-word contains length-displacement information.
  For Yay0/Yaz0, a half-word contains the former, however, a nibble
  with a value of 0 serves as a flag to utilize a byte from "defs" for
  supplemental length values.
  --------------------------------------------------------------------*/
  u32 poly  = 0;
  /*---------------------------------------------------------------------
  Position for Definitive variables.
  For MIO0/SMSR00, this is simply for literal byte copies.
  For Yay0/Yaz0, it is either the former, or a supplementary length byte.
  With Yay0, "defs" is within the designated partition.
  With Yaz0, "defs" represents the entirety of the encoded block.
  ---------------------------------------------------------------------*/
  u32 defs  = 0;
  u32 displacement;
  i32 operations;

  if ( (sizeDecoded == 0) || (sizeDecoded >= 0x3FFFFFFFU) )
  {
    return;
  }

  if ( (*dst = (u8 *)calloc( sizeDecoded, sizeof(u8) )) == (u8 *)0 )
  {
    return;
  }
  
  dest = *dst + sizeDecoded;

  if ( magic != Yaz )
  {
    if ( magic != SMSR )
    {
      poly = _swap32( *(u32 *)&srcbuf[position + 0x08U] );
      defs = _swap32( *(u32 *)&srcbuf[position + 0x0CU] );

      if ( (poly == 0) || (defs < poly) )
      {
        return;
      }

      poly += position;
      defs += position;
      flags = position + 0x10U;
    }
    else
    {
      defs = _swap32( *(u32 *)&srcbuf[position + 0x1CU] );

      if ( defs == 0 )
      {
        return;
      }

      defs += position + 0x20U;
      poly  = position + 0x20U;
    }
  }
  else
  {
    if (    (_swap32( *(u32 *)&srcbuf[position + 0x08U] ) != 0)
         || (_swap32( *(u32 *)&srcbuf[position + 0x0CU] ) != 0) )
    {
      return;
    }

    defs = position + 0x10U;
  }

  do
  {
    if ( masks == 0 )
    {
      if ( magic != Yaz )
      {
        if ( magic != SMSR )
        {
          operations = (i32)_swap32( *(u32 *)&srcbuf[flags] );
          masks  = 32U;
          flags += 4U;
        }
        else
        {
          operations = (i32)_swap16( *(u16 *)&srcbuf[poly] );
          operations <<= 0x10;
          masks = 16U;
          poly += 2U;
        }
      }
      else
      {
        operations   = (i32)srcbuf[defs++];
        operations <<= 0x18;
        masks = 8U;
      }
    }
    else
    {
      if ( operations >= 0 )
      {
        displacement = (u32)_swap16( *(u16 *)((magic != Yaz) ?
                                              &srcbuf[poly]  :
                                              &srcbuf[defs]) );
        previous = *dst - ((displacement & 0x00000FFFU) + 1U);

        if ( magic != Yaz )
        {
          poly += 2U;
        }
        else
        {
          defs += 2U;
        }

        if (    ((displacement >> 12) == 0)
             && (magic != MIO)
             && (magic != SMSR) )
        {
          displacement = (u32)srcbuf[defs++] + 18U;
        }
        else
        {
          displacement = (displacement >> 12) + 2U;

          if ( (magic == MIO) || (magic == SMSR) )
          {
            ++displacement;
          }
        }

        while ( *(*dst)++ = *previous++, --displacement );
      }
      else
      {
        *(*dst)++ = srcbuf[defs++];
      }

      operations <<= 1;
      --masks;
    }
  }
  while ( *dst < dest );
  
  *dst -= sizeDecoded;

  return;
}



static void writeSLI( const u8 *srcbuf,
                      register u32 *position, const u32 blockLength,
                      u32 *hits, const u32 fourCC, const u32 magic,
                      const char *gameID,
                      const char *gameName,
                      const char *path )
{
  FILE *SLI     = (FILE *)0;
  FILE *DECODED = (FILE *)0;
  char *dataEntry   = (char *)calloc( FILENAME_MAX, sizeof(char) );
  char *decodedDest = (char *)0;

  if ( dataEntry == (char *)0 )
  {
    if ( options.verbose != 0 )
    {
      printf( "\n>>> Unable to allocate for file name!\n\n" );
    }

    goto err;
  }

  if ( options.toDecode != 0 )
  {
    decodedDest = (char *)calloc( FILENAME_MAX, sizeof(char) );

    if ( decodedDest == (char *)0 )
    {
      if ( options.verbose != 0 )
      {
        printf( "\n>>> Unable to allocate for decoded file name!\n\n" );
      }

      goto err;
    }
  }

  if ( ((fourCC != 0) && (options.useGameName != 0)) )
  {
    sprintf( dataEntry, "%s[%s]_%s_[0x%X]",
             path, gameID, gameName, *position );
  }
  else
  {
    sprintf( dataEntry, "%s0x%X", path, *position );
  }

  if ( options.toDecode != 0 )
  {
    sprintf( decodedDest, "%s", dataEntry );
  }

  strcat( dataEntry, ((magic != Yaz) ? EXT_SZP : EXT_SZS) );

  if ( (SLI = fopen( dataEntry, "wb" )) == (FILE *)0 )
  {
    if ( options.verbose != 0 )
    {
      printf( "\n>>> Unable to create SLI file!\n\n" );
    }

    goto err;
  }

  if ( options.toDecode != 0 )
  {
    if ( (DECODED = fopen( decodedDest, "wb" )) == (FILE *)0 )
    {
      if ( options.verbose != 0 )
      {
        printf( "\n>>> Unable to create Decoded file!\n\n" );
      }

      goto err;
    }
  }

  if ( options.toDecode != 0 )
  {
    u32 sizeDecoded = 0;
    u8 *dst = (u8 *)0;

    if ( magic == SMSR )
    {
      sizeDecoded = _swap32( *(u32 *)&srcbuf[*position + 0x08U] );
    }
    else
    {
      sizeDecoded = _swap32( *(u32 *)&srcbuf[*position + 0x04U] );
    }
    
    decbuf( srcbuf, &dst, *position, magic, sizeDecoded );

    if ( dst == (u8 *)0 )
    {
      if ( options.verbose != 0 )
      {
        printf( "\n>>> Unable to decode data segment!\n\n" );
      }

      goto err;
    }
    else
    {
      fwrite( dst, sizeof(u8), sizeDecoded, DECODED );
      fflush( DECODED );
      fclose( DECODED );
      free( dst );
      dst = (u8 *)0;
    }
  }

  srcbuf += *position;
  fwrite( srcbuf, sizeof(u8), blockLength, SLI );
  *position += blockLength;
  srcbuf -= *position;
  fflush( SLI );
  fclose( SLI );
  free( decodedDest );
  decodedDest = (char *)0;
  free( dataEntry );
  dataEntry = (char *)0;
  (*hits)++;
  return;

err:

  *position = cleanUpOnError( SLI, DECODED, dataEntry, decodedDest );
  return;
}



static int getBlockLength( const u8 *srcbuf, const u32 position,
                           const u32 magic, register u32 *blockLength )
{
  u32 offset = 0;
  u32 masks  = 0;
  u32 flags  = 0;
  u32 poly   = 0;
  u32 defs   = 0;
  u32 displacement;
  u32 sizeDecoded = _swap32( *(u32 *)&srcbuf[position + 0x04U] );
  i32 operations;

  if ( (sizeDecoded == 0) || (sizeDecoded >= 0x3FFFFFFFU) )
  {
    return EXIT_FAILURE;
  }

  if ( magic != Yaz )
  {
    poly = _swap32( *(u32 *)&srcbuf[position + 0x08U] );
    defs = _swap32( *(u32 *)&srcbuf[position + 0x0CU] );

    if ( (poly == 0) || (defs < poly) )
    {
      return EXIT_FAILURE;
    }

    poly += position;
    defs += position;
    flags = position + 0x10U;
  }
  else
  {
    if (    (_swap32( *(u32 *)&srcbuf[position + 0x08U] ) != 0)
         || (_swap32( *(u32 *)&srcbuf[position + 0x0CU] ) != 0) )
    {
      return EXIT_FAILURE;
    }

    defs = position + 0x10U;
  }

  *blockLength = 16U;

  do
  {
    if ( masks == 0 )
    {
      if ( magic != Yaz )
      {
        operations = (i32)_swap32( *(u32 *)&srcbuf[flags] );
        masks  = 32U;
        flags += 4U;
        *blockLength += 4U;
      }
      else
      {
        operations = (i32)srcbuf[defs++];
        operations <<= 0x18;
        masks = 8U;
        *blockLength += 1U;
      }
    }
    else
    {
      if ( operations >= 0 )
      {
        displacement = (u32)_swap16( *(u16 *)((magic != Yaz) ?
                                              &srcbuf[poly]  :
                                              &srcbuf[defs]) );

        if ( magic != Yaz )
        {
          poly += 2U;
        }
        else
        {
          defs += 2U;
        }

        if ( ((displacement >> 12) == 0) && (magic != MIO) )
        {
          displacement  = srcbuf[defs++] + 18U;
          *blockLength += 3U;
        }
        else
        {
          displacement = (displacement >> 12) + 2U;

          if ( magic == MIO )
          {
            ++displacement;
          }

          *blockLength += 2U;
          }

        offset += displacement;
      }
      else
      {
        ++defs;
        ++offset;
        (*blockLength)++;
      }

      operations <<= 1;
      --masks;
    }
  }
  while ( offset < sizeDecoded );

  return EXIT_SUCCESS;
}



static void postDiscrepancy( const u8 *srcbuf,
                             const u32 position, const u32 oddities )
{
  printf( "___[#%u]___QUESTIONABLE_DATA_SEQUENCE___\n"
          "0x%X -> [0x%X]\n0x%X -> [0x%X]\n0x%X -> [0x%X]\n0x%X -> [0x%X]\n",
          oddities,
          position, _swap32(*(u32 *)(srcbuf + position)),
          (u32)(position + 0x4U), _swap32(*(u32 *)&srcbuf[position + 0x04U]),
          (u32)(position + 0x8U), _swap32(*(u32 *)&srcbuf[position + 0x08U]),
          (u32)(position + 0xCU), _swap32(*(u32 *)&srcbuf[position + 0x0CU]) );
  return;
}



static void scanSLI( u8 *srcbuf,
                     const u32 lengthROM, const u32 fourCC,
                     const char *path )
{
  /*----------------------
  FourCC + NULL Terminator
  ----------------------*/
  char gameID[5];
  /*-----------------------------
  20 Byte Frame + NULL Terminator
  -----------------------------*/
  char gameName[21];
  u32 magic = 0;
  u32 id32  = 0;
  u32 blockLength = 0;
  u32 hits = 0;
  u32 oddities = 0;
  u32 position = 0;
  unsigned hasGZIP = 0;
  /*------------------------------------------------------------
  Some enumerated values pertaining to Game IDs for titles that
  have quirks, or are problematic from unresolved discrepancies.
  ------------------------------------------------------------*/
  enum
  {
    /*--------------------
    Game IDs: Body Harvest
    --------------------*/
    NBHE = 0x4E424845U, /* NTSC */
    NBHP = 0x4E424850U, /* PAL */
    /*------------------------------------------------------
    Game IDs: Looney Tunes: Duck Dodgers Starring Daffy Duck
    ------------------------------------------------------*/
    /*NDUE = 0x4E445545,
    NDUP = 0x4E445550,*/
    /*----------------------------------------
    Game IDs: Scooby-Doo! Classic Creep Capers
    ----------------------------------------*/
    NSYE = 0x4E535945U, /* NTSC */
    NSYP = 0x4E535950U  /* PAL */
  };

  if ( (fourCC != 0) && (options.useGameName != 0) )
  {
    int j = 0;

    id32 = _swap32( *(u32 *)&srcbuf[0x3BU] );

    while ( j < 4 )
    {
      gameID[j] = (char)srcbuf[0x3BU + j];
      ++j;
    }

    gameID[j] = '\0';
    j = 0;

    while ( j < 20 )
    {
      gameName[j] = (char)srcbuf[0x20U + j];

      if ( j < 19 )
      {
        if ( (gameName[j] == ' ') && (gameName[j + 1] != ' ') )
        {
          gameName[j] = '_';
        }

        if ( (((char)srcbuf[0x20U + j    ] == (char)0x20U) &&
              ((char)srcbuf[0x20U + j + 1] == (char)0x20U)) )
        {
          goto space;
        }
      }
      else
      {
space:  gameName[j] = '\0';
        break;
      }

      ++j;
    }
  }

  while ( position < lengthROM )
  {
    magic = _swap32( *(u32 *)&srcbuf[position] );

    if ( (magic == MIO) || (magic == Yay) || (magic == Yaz) )
    {
      /*-----------------------------------------------------------
      Hack to keep from crashing when dumping from Scooby-Doo! CCC.
      This hasn't been tested for accuracy or inadvertent deficits.
      -----------------------------------------------------------*/
      if ( (id32 == NSYE) || (id32 == NSYP) )
      {
        if ( (position & 1) != 0 )
        {
          ++oddities;

          if ( options.verbose != 0 )
          {
            postDiscrepancy( srcbuf, position, oddities );
          }

          goto next;
        }
      }

      if ( magic == MIO )
      {
        if ( (id32 == NBHE) || (id32 == NBHP) )
        {
          /*----------------------------------------------------
          DMA Design Limited [a.k.a. Rockstar North] used a
          non-standard SLI header in their title "Body Harvest".
          Instead of using the standard 16-Byte header,
          they used a 20-Byte header that deviates as such:

          MM = Magic, DD = DecodedSize,
          PP = Offset to Pointers, RR = Offset to Raw Bytes

          MMMMMMMM BLOCKLEN DDDDDDDD PPPPPPPP
          RRRRRRRR
          ----------------------------------------------------*/
          position += 4U;
          blockLength = _swap32( *(u32 *)&srcbuf[position] ) - 4U;
          *(u32 *)&srcbuf[position        ] = _swap32( magic );
          *(u32 *)&srcbuf[position + 0x08U] =
            _swap32( _swap32( *(u32 *)&srcbuf[position + 0x08U] ) - 4U );
          *(u32 *)&srcbuf[position + 0x0CU] =
            _swap32( _swap32( *(u32 *)&srcbuf[position + 0x0CU] ) - 4U );
          writeSLI( srcbuf, &position, blockLength,
                    &hits, fourCC, magic,
                    gameID, gameName, path );

          if ( position == 0 )
          {
            return;
          }

          goto next;
        }
        else
        {
          /*------------------------------------------------------------
          Hack to keep the program from crashing when dumping from
          Looney Tunes: Duck Dodgers Starring Daffy Duck.
          It seems that if the FourCC "MIO0" isn't preceded by "GZIP"
          16 bytes prior, the "MIO0" header contains unusual information
          at 0x8 and 0xC which will cause this program to crash.
          ------------------------------------------------------------*/
          u32 code = _swap32( *(u32 *)&srcbuf[position - 0x10U] );

          if ( !hasGZIP && (code == GZIP) )
          {
            hasGZIP = !hasGZIP;
          }
          else
          {
            if ( hasGZIP && (code != GZIP) )
            {
              ++oddities;

              if ( options.verbose != 0 )
              {
                postDiscrepancy( srcbuf, position, oddities );
              }

              goto next;
            }
          }
        }
      }
      /*------------------------------------------------
      Function returns "0" on success, and "1" on error.
      "blockLength" is the true recipient variable
      pertaining to the function's implicit descriptor.
      ------------------------------------------------*/
      if ( getBlockLength( srcbuf, position, magic, &blockLength ) == 0 )
      {
        writeSLI( srcbuf, &position, blockLength,
                  &hits, fourCC, magic,
                  gameID, gameName, path );

        if ( position == 0 )
        {
          return;
        }
      }
      else
      {
        ++oddities;

        if ( options.verbose != 0 )
        {
          postDiscrepancy( srcbuf, position, oddities );
        }

        position += 4U;
      }
    }
    else
    {
      if ( magic == CMPR )
      {
        magic = _swap32(*(u32 *)&srcbuf[position + 0x10U]);

        if ( magic == SMSR )
        {
          blockLength = _swap32(*(u32 *)&srcbuf[position + 0x04U]);
          writeSLI( srcbuf, &position, blockLength,
                    &hits, fourCC, magic,
                    gameID, gameName, path );

          if ( position == 0 )
          {
            return;
          }
        }
      }
      else
      {
next:   ++position;
      }
    }
  }

  printf( "# Hits: %u\n# Oddities: %u\n", hits, oddities );
  return;
}



static void  _usage( void );
static char *_processArgs();
static int   _closeROM();
static void  _getPath();
static void  _orderBytes();
static int   _writeROM();



int main( const int argc, const char *argv[] )
{
  if ( argc < 2 )
  {
    _usage();
    return EXIT_FAILURE;
  }
  else
  {
    char  pathROM[PPATH_MAX];
    char  cdirROM[PPATH_MAX];
    char *path = (char *)0;
    FILE *ROM  = (FILE *)0;

    if ( (path = _processArgs( argc, argv )) == (char *)0 )
    {
      return EXIT_FAILURE;
    }

    strcpy( pathROM, path );
    strcpy( cdirROM, path );

    if ( (ROM = fopen( pathROM, "rb" )) == (FILE *)0 )
    {
      free( path );
      path = (char *)0;
      printf( "\n>>> Unable to open:\n>>> \"%s\"\n\n", pathROM );
      return EXIT_FAILURE;
    }
    else
    {
      u8 *srcbuf = (u8 *)0;
      u32 lengthROM;

      fseek( ROM, 0L, SEEK_END );
      lengthROM = (u32)ftell( ROM );

      if (    (lengthROM == (u32)EOF)
           || (lengthROM >= 0x3FFFFFFF)
           || (lengthROM == 0) )
      {
        printf( "\n>>> Unsupported ROM file size!\n\n" );
        return _closeROM( ROM, 1 );
      }
      else
      {
        if ( (srcbuf = (u8 *)calloc( lengthROM, sizeof(u8) )) == (u8 *)0 )
        {
          printf( "\n>>> Error allocating RAM for ROM buffer!\n\n" );
          return _closeROM( ROM, 1 );
        }
        else
        {
          rewind( ROM );

          if ( (u32)fread( srcbuf, sizeof(u8), lengthROM, ROM ) != lengthROM )
          {
            printf( "\n>>> Error reading from ROM file into buffer!\n\n" );
            return _closeROM( ROM, 1 );
          }
          else
          {
            u32 magic  = _swap32( *(u32 *)srcbuf );
            u32 fourCC = 0;

            fclose( ROM );
            _getPath( cdirROM );
            fourCC = (((magic == 0x80371240U) << 3) |
                      ((magic == 0x40123780U) << 2) |
                      ((magic == 0x37804012U) << 1) |
                       (magic == 0x12408037U));

            if ( fourCC == 0 )
            {
              printf( "# Not an N64 ROM!\n"
                      "# Will attempt to scan for Big-Endian SLI data.\n" );

              if ( options.useGameName != 0 )
              {
                options.useGameName = 0;
                printf( "<USE-GAME-NAME:  DISABLED>\n" );
              }

              if ( options.writeROM != 0 )
              {
                options.writeROM = 0;
                printf( "<WRITE-BE-ROM:   DISABLED>\n" );
              }
            }
            else
            {
              if ( (fourCC & 8U) == 0 )
              {
                if ( (lengthROM & 3) != 0 )
                {
                  printf( "# ROM isn't 32-bit aligned...\n"
                          "# Aligning.\n" );

                  while ( (lengthROM & 3) != 0 )
                  {
                    ++lengthROM;
                  }

                  if (    (srcbuf = (u8 *)realloc( srcbuf, lengthROM ))
                       == (u8 *)0 )
                  {
                    printf( "\n>>> Unable to extend for alignment!\n\n" );
                    return EXIT_FAILURE;
                  }
                }

                printf( "# Found Nintendo 64 ROM Magic!\n"
                        "# Ordering bytes to Big-Endian.\n" );
                _orderBytes( srcbuf, fourCC, lengthROM );

                if ( options.writeROM != 0 )
                {
                  if ( _writeROM( srcbuf, lengthROM, pathROM ) != 0 )
                  {
                    return EXIT_FAILURE;
                  }
                }
              }
            }

            scanSLI( srcbuf, lengthROM, fourCC, cdirROM );

            if ( srcbuf != (u8 *)0 )
            {
              free( srcbuf );
              srcbuf = (u8 *)0;
            }

            printf( "# %u seconds elapsed.\n",
                    (u32)(clock() / CLOCKS_PER_SEC) );
            return EXIT_SUCCESS;
          }
        }
      }
    }
  }
}



static void _usage( void )
{
  printf( "\n## SLI Extractor [Nintendo 64] ##\n"
          ">> WGTDS [2021/10/30]\n\n" );
  printf( "Usage: xsli [options] [ROMfile]\n\n"
          "  -d    :   Decode SLI data into new files.\n"
          "  -g    :   Use internal game name for files.\n"
          "  -o    :   Write Big-Endian ROM.\n"
          "  -v    :   Enable verbose messages.\n" );
}



static int _closeROM( FILE *ROM, const int code )
{
  fclose( ROM );
  return code;
}



static void _getPath( char *cdirROM )
{
  register int i = 0;

  while ( cdirROM[i] != '\0' )
  {
    ++i;
  }

  while ( (cdirROM[i] != '\\') && (cdirROM[i] != '/') && (i >= 0) )
  {
    cdirROM[i--] = '\0';
  }

  return;
}



static char *_processArgs( const int argc, char *argv[] )
{
  char *pathROM;
  int c;
  int f = 0;
  int i = 1;

  if ( (pathROM = (char *)malloc( sizeof(char) * PPATH_MAX )) == (char *)0 )
  {
    printf( "\n>>> Unable to allocate work RAM for the file path!\n\n" );
    goto err;
  }

  options.toDecode    = 0;
  options.useGameName = 0;
  options.writeROM    = 0;
  options.verbose     = 0;

  while ( i < argc )
  {
    if ( argv[i][0] == '-' )
    {
      switch ( c = toupper( argv[i][1] ) )
      {
        case 'D':
          options.toDecode = 1;
          printf( "<DECODING:       ENABLED>\n" );
          break;
        case 'G':
          options.useGameName = 1;
          printf( "<USE-GAME-NAME:  ENABLED>\n" );
          break;
        case 'O':
          options.writeROM = 1;
          printf( "<WRITE-BE-ROM:   ENABLED>\n" );
          break;
        case 'V':
          options.verbose = 1;
          printf( "<VERBOSITY:      ENABLED>\n" );
          break;
        default:
          printf( "\n>>> Unrecognized Option: \"%c\"\n\n", (char)c );
          break;
      }
    }
    else
    {
      if ( f != 1 )
      {
        if ( strlen( argv[i] ) >= PPATH_MAX )
        {
          printf( "\n>>> Path length is too long!\n\n" );
          goto err;
        }
        else
        {
          pathROM = argv[i];
          f = 1;
        }
      }
      else
      {
        printf( "\n>>> Erroneous arguments!\n\n" );
        goto usg;
      }
    }

    ++i;
  }

  if ( f == 0 )
  {
    printf( "\n>>> No ROM file to process!\n\n" );
    goto usg;
  }

  return pathROM;

usg:

  _usage();

err:

  if ( pathROM != (char *)0 )
  {
    free( pathROM );
  }

  return pathROM = (char *)0;
}



static void _orderBytes( u8 *srcbuf, const u32 fourCC, const u32 lengthROM )
{
  enum
  {
    ENDIAN_BS_LITTLE = 1,
    ENDIAN_BS_BIG    = 2,
    ENDIAN_LITTLE    = 4,
    ENDIAN_BIG       = 8
  };
  register u32 i = 0;

  do
  {
    /*---------------------------------------------------------
    Recognized Byte Ordering:
        0x80371240 [ABCD, Big-Endian][Native to the Nintendo64]
        0x40123780 [DCBA, Little-Endian]
        0x37804012 [BADC, Byte-Swapped Big-Endian]

        Unrecognized Byte Ordering:
        0x12408037 [CDAB, Byte-Swapped Little-Endian]
    ---------------------------------------------------------*/
    /*---------------------------------
    For DCBA and arranging CDAB to BADC
    ---------------------------------*/
    if ( fourCC != ENDIAN_BS_BIG )
    {
      *(u32 *)&srcbuf[i] = _swap32( *(u32 *)&srcbuf[i] );
    }
    /*------
    For BADC
    ------*/
    if ( fourCC != ENDIAN_LITTLE )
    {
      *(u16 *)&srcbuf[i    ] = _swap16( *(u16 *)&srcbuf[i    ] );
      *(u16 *)&srcbuf[i + 2] = _swap16( *(u16 *)&srcbuf[i + 2] );
    }

    i += 4;
  }
  while ( i < lengthROM );

  return;
}



static int _writeROM( const u8 *srcbuf, const u32 lengthROM,
                      const char *pathROM )
{
  FILE *ROM = (FILE *)0;
  char newPathROM[PPATH_MAX + 8];
  register unsigned i = 0;

  i = (unsigned)strlen( strcpy( newPathROM, pathROM ) );

  do
  {
    if ( newPathROM[i] == '.' )
    {
      strcpy( &newPathROM[i], "_bs.N64" );
      break;
    }
    else
    {
      if ( (newPathROM[i] == '\\') || (newPathROM[i] == '/') )
      {
        strcat( newPathROM, "_bs.N64" );
        break;
      }
      else
      {
        --i;
      }
    }
  }
  while ( 1 );

  if ( (ROM = fopen( newPathROM, "wb" )) == (FILE *)0 )
  {
    return EXIT_FAILURE;
  }
  else
  {
    fwrite( srcbuf, sizeof(u8), lengthROM, ROM );
    srcbuf -= lengthROM;
    fflush( ROM );
    fclose( ROM );
    return EXIT_SUCCESS;
  }
}
