#ifndef Reader_h
#define Reader_h
#include "Arduino.h"
class Reader
{
	public:
		Reader();
		//Request For Tag and Saves it Type		
		bool PICC_Request(byte md);

		//Mifare Anticollision Return 1 if 1 Tag Detected and Save Serial Number on variable
		bool PICC_Anticollision();

		//Mifare Select Acknowledge Command
		void PICC_SAK();

		//Mifare PICC SAK Value Function
		int PICC_SAKV();

		//Setting immediate Key Function for Ultralight C 3DES authentication on Reader
		void PCD_SIKEY_UL(byte *Key, size_t len);

		//SToring Key Function for Ultralight C 3DES authentication on Reader
		bool PCD_SET_BLK_KEY_UL(byte *Key, size_t len, byte blk);

		//LOAD KEY FROM READERS BLOCK FOR AUTHENTICATION
		bool PCD_LDKEY_UL(byte blk);

		//3DES Authentication Function For Ultralight C
		bool PCD_UL_3DES();

		//Ultralight C reading Block Function
		void PCD_ULC_READ(byte blk);
		void PCD_ULC_READs(byte blk);
		
		//Ultralight C Writing block Function
		void PCD_ULC_WRITE(byte blk, byte *ptr);

		//Ultralight C Read Authentication Mode
		void PICC_READ_ULC_AUTH();

		//Write 3DES KEY to TAG/CARD
		bool PCD_WRITE_3DES_ULC(byte *ptr, size_t len);
		
		//Set ultralight C Tag Authentication Mode
		void PICC_SET_AUTH_MD();

		//Storing Key Function on Reader
		bool PCD_WRITE_KEY_EEPROM(byte *Key, size_t len, byte Gn); //Store Key on EEPROM group 0-31 GN

		//Mifare Authentication 1 using Stored Key on EEPROM of Reader
		bool PICC_AUTH_1(byte md, byte blk, byte Gn);

		//Mifare Authentication 2 Function
		bool PICC_AUTH_2(byte md, byte blk, byte *ptr, size_t len);

		//Mifare Authentication 3 Function
		bool PICC_AUTH_3(byte md, byte blk, byte *ptr, size_t len);

		//Perform HALTA Command
		void PCD_HALTA();

		void PICC_Initial();
		
		bool PICC_Anti_ul();
		bool PCD_3DES();
		void PCD_UL_3DES2();

};

#endif