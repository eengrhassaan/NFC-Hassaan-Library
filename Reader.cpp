#include <Reader.h>
//======================= RX DATA VARAIBLES ==================//
byte Rx_buffer[255];
byte XOR;
byte UID7[7];
byte UID4[4];
int ATQA = 0x0000;
int counters1 = 0;
String Tagtype;
/************************ CR013 Plus Type A B RFID Reader Commands Packets ************************/
//======================= General Tag Commands ATQA / SAK / Anticollision  ========================
/* request Tag All Command (0x0201 Request Command lower byte First) &
(0x52) is for Request All &(0x26 is for request IDLE)
*/
byte rqa_card[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x01, 0x02, 0x52, 0x51 };
byte rqi_card[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x01, 0x02, 0x26, 0x25 };
//Anticollision ULTRALIGHT C Command (0x0212) is anticollision Command 
byte anti[]={0xaa, 0xbb, 0x05, 0x00, 0x00, 0x00, 0x12, 0x02, 0x10};
//mifare Classic Anticollision Command (0x0202) is anticollision Command
byte anti_col[] = { 0xAA, 0xBB, 0x05, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00 };
//Mifare Select Command (0x0203) is the SAK Command and 0x11 to 0x44 is 4 byte UID it may be of 7 bytes
byte sak4[] = { 0xAA, 0xBB, 0x09, 0x00, 0x00, 0x00, 0x03, 0x02, 0x11, 0x22, 0x33, 0x44, 0x00 };
byte sak7[] = { 0xAA, 0xBB, 0x09, 0x00, 0x00, 0x00, 0x03, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00 };
//Mifare HaltA command
byte halta[] = { 0xAA, 0xBB, 0x05, 0x00, 0x00, 0x00, 0x04, 0x02, 0x06 };

//======================= UltralightC commands Packets for READ/WRITE/AUTH ========================
//Set Key to Reader for Authentication Command Packets
//default 0 group 0x0AFC set key command after command
// 0x00 is the group number
byte key1_ul[] = { 0xAA, 0xBB, 0x1E, 0x00, 0x00, 0x00,
				   0xFC, 0x0A, 0x00, 0x00, 0x01, 0x02,
				   0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
				   0x0F, 0x00, 0x00, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0xF7 };
			 
//Set Immediate Key to Reader for Authentication Command Packets
byte keyi_ul[] = { 0xAA, 0xBB, 0x1E, 0x00, 0x00, 0x00, 0xFC,
				   0x0A, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
				   0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				   0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00,
				   0x00, 0x00, 0x00, 0x00, 0x00, 0x09 };
				
//Load Key to Reader Command packet 2nd last byte 0x00 is the group Number
/* Group 0 ====> 0x00
 * Group 1 ====> 0x01
 * Group 2 ====> 0x02
 * Group 3 ====> 0x03
 * Group 4 ====> 0x04
 * Group 5 ====> 0x05
 * Group 6 ====> 0x06
 * Group 7 ====> 0x07
 * Immediate Key====> 0xFF
 By default we select Group 0
*/ 
byte load_key[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0xFD, 0x0A, 0x00, 0x00 };

/* Ultralight C/ Mifare Classic Read Data Command 0x04 second last byte
 is the Block Address from which reader Reads the Data */
byte rd_tag[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x08, 0x02, 0x1E, 0x14 };

/* Ultralight C Writing TAG Commands 0x0213
 * After 0x0213 the byte 0x04 the Address of Block to whgich Data will be written
 * And the Consecutives Four Byte 0x88 are the Data that will be write on the 
 * above Mentioned Block ===> By default Block is 0x04
 * =========================> By default data is (0x88,0x88,0x88,0x88)
 */
byte write_tag[] = { 0xAA, 0xBB, 0x0A, 0x00, 0x00, 0x00, 0x13, 0x02, 0x04, 0x88, 0x88, 0x88, 0x88, 0x15 };

//Authentication Step 1 & Step 2 commands
byte ul_auth_step1[] = { 0xAA, 0xBB, 0x05, 0x00, 0x00, 0x00, 0x14, 0x02, 0x3C };
byte ul_auth_step2[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x15, 0x02, 0x2A, 0x3D };

//Read Authentication Mode Command
byte rd_auth_md[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x08, 0x02, 0x2A, 0x20 };

//Set Tag Authentication Mode
byte st_ulauth_md1[] = { 0xAA, 0xBB, 0x0A, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2A, 0x27, 0x00, 0x00, 0x00, 0x1C };
byte st_ulauth_md2[] = { 0xAA, 0xBB, 0x0A, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2B, 0x01, 0x00, 0x00, 0x00, 0x3B };

//Write 3DES Key to ultralight C Command
//if KEY = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
byte write_auth_key1[] = { 0xAA, 0xBB, 0x0A, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2C, 0x07, 0x06, 0x05, 0x04, 0x3D };
byte write_auth_key2[] = { 0xAA, 0xBB, 0x0A, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2D, 0x03, 0x02, 0x01, 0x00, 0x3C };
byte write_auth_key3[] = { 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2E, 0x0F, 0x0E, 0x0D, 0x0C, 0x3F };
byte write_auth_key4[] = { 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x13, 0x02, 0x2F, 0x0B, 0x0A, 0x09, 0x08, 0x3E };
//======================= UltralightC commands Packets for READ/WRITE/AUTH ========================



//======================= Mifare Tags commands Packets for READ/WRITE/AUTH ========================
//mifare authentication 3 (0x0225) is the authentication commands
// 0x60  is for Key A and 0x61 for Key B and after that 0x04 is the block addresss for authentication
byte mf_auth3[] = { 0xAA, 0xBB, 0x0D, 0x00, 0x00, 0x00,
					 0x25, 0x02, 0x60, 0x04, 0xff, 0xff,
					 0xff, 0xff, 0xff, 0xff, 0x43 };

//Mifare authentication 1 using EEPROM Store Key
//0x0206 is the command for Key using from EEPROM
//0x60 is the authentication mode 0x60=keyA and 0x61 is keyB
//0x04 Block authenctication and 0x01 is the Group 
//where keys are stored from group 0-31 (32 EEPROM KEYS)
//11th bytes needs to be change w.r.t Group number provided
byte mf_auth1[] = { 0xAA, 0xBB, 0x08, 0x00, 0x00, 0x00,
					 0x06, 0x02, 0x60, 0x04, 0x01, 0x61 };

//Mifare authentication 2 0x60 is KEYA
//Mifare authentication 2 0x61 is KEYB 0x04 is the block address
byte mf_auth2[]={0xAA, 0xBB, 0x0D, 0x00, 0x00, 0x00,
				  0x07, 0x02, 0x60, 0x04, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff, 0x61};


//Read Command 0x0208
byte mf_read[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00, 0x08, 0x02, 0x04, 0x0E };

//Write Command 0x0209 0x04 is the Block address
//after block address from 0x00 to ox56 is the 16 bytes data
byte mf_write[] = { 0xAA, 0xBB, 0x06, 0x00, 0x00, 0x00,
					0x09, 0x02, 0x04, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x12, 0x34, 0x78,
					0x56, 0x07 };

//Write Key to EEPROM 0x0216 write key to eeprom 
//0x60 auth mode igonred in this command
//0x01 is the group number for KEY storing
//0xFF will be the KEY
byte mf_stkey[] = { 0xAA, 0xBB, 0x0D, 0x00, 0x00, 0x00,
					0x16, 0x02, 0x60, 0x01, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0x75 };

//default constructor
Reader::Reader()
{
	
}

//Readers Initialization

//============================== PICC Request Start =====================================
bool Reader::PICC_Request(byte md)
{
	//if mode is request All then we use rq_a variable
	if ((md=='a') || (md=='A'))
	for (int cnt = 0; cnt < sizeof(rqa_card); cnt++)
		//Sending Command of Request ALL
	{
		Serial2.write(rqa_card[cnt]);
		//Serial.print(rqa_card[cnt],HEX);
	}
	else if ((md == 'i') || (md == 'I'))
		for (int cnt = 0; cnt < sizeof(rqi_card); cnt++)
		//Receiving Command of Request Idle	
		{
			Serial2.write(rqi_card[cnt]);
			//Serial.print(rqi_card[cnt], HEX);
		}	
	
	//Recieving the Reader's Response
	counters1 = 0;
	delay(10);
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	Serial.println(">>");
	Serial2.flush();
	Serial.flush();
	//Check whether the Card/present or Not if present then its type
	if ((Rx_buffer[9] == 0x44) && (Rx_buffer[10] == 0x00))		//0x44 is Ultralight
	{
		Tagtype = "Ultralight"; 
		ATQA = 0x0044;
		return 1;
	}

	//Check whether the Card/present or Not if present then its type
	else if (Rx_buffer[9] == 0x04)		//0x04 is Mifare One (S50)
	{
		Tagtype = "Mifare One(S50)";
		ATQA = 0x0004;
		return 1;
	}

	//Check whether the Card/present or Not if present then its type
	else if (Rx_buffer[9] == 0x02)		//0x02 is Mifare one (S70)
	{
		Tagtype = "Mifare One(S50)";
		ATQA = 0x0002;
		return 1;
	}
	
	//Check whether the Card/present or Not if present then its type
	else if ((Rx_buffer[9] == 0x44)	&& (Rx_buffer[10] == 0x03))	//0x4403 is Mifare DesFire
	{
		Tagtype = "Mifare DesFire";
		ATQA = 0x4403;
		return 1;
	}

	//Check whether the Card/present or Not if present then its type
	else if (Rx_buffer[9] == 0x08)		//0x08 is Mifare_Pro
	{
		Tagtype = "Mifare Pro";
		ATQA = 0x0008;
		return 1;
	}
	
	//Check whether the Card/present or Not if present then its type
	else if ((Rx_buffer[9] == 0x04) && (Rx_buffer[10] == 0x03))		//0x0403 is Mifare_prox
	{
		Tagtype = "Mifare Pro";
		ATQA = 0x0403;
		return 1;
	}

	else
	{
		//ATQA = 0x0044;
		//Serial.print("  ");
		//Serial.print(ATQA, HEX);
		return 0;
	}
}
//============================== PICC Request END  ======================================

//======================= PICC AntiCollision Start ======================================
bool Reader::PICC_Anti_ul()
{
	for (int cnt1 = 0; cnt1 < 9; cnt1++)
		Serial2.write(anti[cnt1]);
	counters1=0x00;
	Serial.print("\n Here: ");
	delay(10);
	while(Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	Serial.println("<<");
	return true;
}

//======================= PICC AntiCollision Start ======================================



//======================= PICC AntiCollision Start ======================================
bool Reader::PICC_Anticollision()
{
	
	//Serial.println(Tagtype);
	//ultralight tag Anticollision
	if (ATQA == 0x0044) 
	for (int cnt1 = 0; cnt1 < sizeof(anti); cnt1++)
	{
		Serial2.write(anti[cnt1]);
		//Serial.print(antiul_col[cnt1], HEX);
		//Serial.print(" ");
	}
	//other than Ultralight Tags
	else
		for (int cnt1 = 0; cnt1 < sizeof(anti); cnt1++)
			Serial2.write(anti[cnt1]);
	
	//Receiving Serial Data
	counters1 = 0;
	delay(400);
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	Serial.println();
	//For Ultralight
	if ((ATQA == 0x0044) || (ATQA == 0x0004))
	{
		for (int cnt1 = 0; cnt1 < 7; cnt1++)
			UID7[cnt1] = Rx_buffer[cnt1 + 9];
		return 1;
	}
	//For other Tags
	else
	{
		for (int cnt1 = 0; cnt1 < 4; cnt1++)
			UID7[cnt1] = Rx_buffer[cnt1 + 9];
		return 1;
	}
	//Unsupported Tags
	//else
		return 0;
}
//===================== PICC Authentication END  ========================================

//============================== PICC SAK Start ==========================================
void Reader::PICC_SAK()
{
	// 7 bytes UID 
	if ((ATQA == 0x0044) || (ATQA == 0x0004))
	{
		//Setting UID on SAK Command
		for (int cnt1 = 0; cnt1 < 7; cnt1++)
			sak7[cnt1 + 8] = UID7[cnt1];

		//Setting XOR byte in SAK Command
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(sak7)-1; cnt1++)
			XOR = XOR^sak7[cnt1];
		sak7[sizeof(sak7)-1] = XOR;

		//Sending Command to Reader From HOST Device
		for (int cnt1 = 0; cnt1 < sizeof(sak7); cnt1++)
			Serial2.write(sak7[cnt1]);
		counters1 = 0;

		delay(10);
		//Getting Reader's Response
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial.print(Rx_buffer[counters1],HEX);
			Serial.print(" ");
			counters1++;
		}
		
		//To See the Status on Serial Monitor
		Serial.print("\n	");
		Serial.print(Rx_buffer[counters1 - 2]);
		return;
	}

	// 4 bytes UID
	else
	{
		//Setting UID on SAK Command
		for (int cnt1 = 0; cnt1 < 3; cnt1++)
			sak4[cnt1 + 8] = UID4[cnt1];

		//Setting XOR Byte
		for (int cnt1 = 4; cnt1 < sizeof(sak4)-1; cnt1++)
			XOR = XOR^sak4[cnt1];
		sak4[sizeof(sak4)-1] = XOR;

		//Sending Command to Reader From HOST Device
		for (int cnt1 = 0; cnt1 < sizeof(sak4); cnt1++)
			Serial2.write(sak4[cnt1]);
		counters1 = 0;

		delay(100);
		//Getting Reader's Response
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}
		//To See on Serial Monitor
		Serial.print("	");
		Serial.print(Rx_buffer[counters1 - 2]);
		return;
	}
}
//============================== PICC SAK ENDS ===========================================

//============================= PICC SAKV Start ==========================================
int Reader::PICC_SAKV()
{
	// 7 bytes UID 
	if ((ATQA == 0x0044) || (ATQA == 0x0004))
	{
		//Setting UID on SAK Command
		for (int cnt1 = 0; cnt1 < 7; cnt1++)
			sak7[cnt1 + 8] = UID7[cnt1];

		//Setting XOR byte in SAK Command
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(sak7)-1; cnt1++)
			XOR = XOR^sak7[cnt1];
		sak7[sizeof(sak7)-1] = XOR;

		//Sending Command to Reader From HOST Device
		for (int cnt1 = 0; cnt1 < sizeof(sak7); cnt1++)
			Serial2.write(sak7[cnt1]);
		counters1 = 0;

		//Getting Reader's Response
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}

		//Serial2.print("	");
		//Serial2.print(Rx_buffer[counters1 - 2]); //Value returning So don't need to print
		return Rx_buffer[counters1 - 2];
	}

	// 4 bytes UID
	else
	{
		//Setting UID in SAK Command
		for (int cnt1 = 0; cnt1 < 3; cnt1++)
			sak4[cnt1 + 8] = UID4[cnt1];

		//Setting XOR Byte
		for (int cnt1 = 4; cnt1 < sizeof(sak4)-1; cnt1++)
			XOR = XOR^sak4[cnt1];
		sak4[sizeof(sak4)-1] = XOR;

		//Sending Command From Reader To HOST
		for (int cnt1 = 0; cnt1 < sizeof(sak4); cnt1++)
			Serial2.write(sak4[cnt1]);
		counters1 = 0;

		//Getting Reader response
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}

		//Serial2.print("	");
		//Serial2.print(Rx_buffer[counters1 - 2]); //Value returning So don't need to print
		return Rx_buffer[counters1 - 2];
	}
}
//============================= PICC SAKV Ends ===========================================



/************ ULTRALIGHT 3DES Authentication/Reading/Writing Functions ******************* 
* Immediate Key Setting To The Reader
* Save Key To the Block
* Load Key from block If not Using Immediate Key
* Two Steps 3DES Authentication
******************************************************************************************/
//============================= PICC SET_I_KEY Start ======================================
void Reader::PCD_SIKEY_UL(byte *Key, size_t len)
{
	Serial.println("\nmethod starting");
	Serial.println(keyi_ul[33],HEX);
	//Setting Key On keyi_ul Variable
	for (int cnt1 = 0; cnt1 < len; cnt1++)
		keyi_ul[cnt1 + 9] = Key[cnt1];
	
	//XOR Calculation for keyi_ul Variable
	XOR = 0x00;
	for (int cnt1 = 4; cnt1 <= 32; cnt1++)
		XOR = XOR^keyi_ul[cnt1];
	keyi_ul[33] = XOR;
	Serial.println(key1_ul[33],HEX);
	//Sending Command to Reader for setting the immediate Key
	for (int cnt1 = 0; cnt1 < sizeof(keyi_ul); cnt1++)
		Serial2.write(keyi_ul[cnt1]);
	delay(100);
	//Recieveing Status
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	Serial.print("\n");
	Serial.println(" ");
	Serial.print(Rx_buffer[counters1-2],HEX);
	Serial.println("\nmethod ending");
	return;
}
//============================= PICC SET_I_KEY ENDS =======================================


//============================= PICC SET_B_KEY STARS ======================================
bool Reader::PCD_SET_BLK_KEY_UL(byte *Key, size_t len, byte blk)
{
	if (blk > 0x07)
		return 0;
	else if (len != 16)
		return 0;
	else
	{
		//Setting block to the Command
		key1_ul[8] = blk;
		//Setting Key on Command
		for (int cnt1 = 0; cnt1 < len; cnt1++)
			key1_ul[cnt1 + 9] = Key[cnt1];
		//XOR Calculation for keyi_ul Variable
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 <= 32; cnt1++)
			XOR = XOR^key1_ul[cnt1];
		key1_ul[33] = XOR;
		//Sending Command to Reader for setting the immediate Key
		for (int cnt1 = 0; cnt1 < sizeof(key1_ul); cnt1++)
			Serial2.write(key1_ul[cnt1]);
		//Recieveing Status
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial.print(Rx_buffer[counters1],HEX);
			Serial.print(" ");
			counters1++;
		}
		Serial.println();
		Serial.print(" ");
		Serial.print(Rx_buffer[counters1 - 2], HEX);
		return 1;
	}
}
//============================= PICC SET_B_KEY ENDS  ======================================


//============================= PICC LOAD_B_KEY STARTS  ===================================
bool Reader::PCD_LDKEY_UL(byte blk)
{
	if (blk < 0x08)
	{
		//Setting Block in Command
		load_key[8] = blk;
		//XOR Calculation for keyi_ul Variable
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 <sizeof(load_key)-1; cnt1++)
			XOR = XOR^load_key[cnt1];
		load_key[9] = XOR;
		//Sending Command To Reader from HOST
		for (int cnt1 = 0; cnt1 < sizeof(load_key); cnt1++)
			Serial2.write(load_key[cnt1]);
		//Reading Reader's Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}
		Serial.print(Rx_buffer[8], HEX);
		return 1;
	}
	else
		return 0;
}
//============================= PICC LOAD_B_KEY STARTS  ===================================


//============================= PICC UL_3DES_AUTHENTICATION STARTS ========================
bool Reader::PCD_UL_3DES()
{
	//Authentication Using step1 Sending Authentication Command
	for (int cnt1 = 0; cnt1 < sizeof(ul_auth_step1); cnt1++)
		Serial2.write(ul_auth_step1[cnt1]);
	
	//Getting Serial response from Reader 
	counters1 = 0;
	delay(100);
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	//Serial.println(Rx_buffer[counters1-2],HEX);
	Serial.println("Authentication 1");
	//Checking Authentication Step one
	if (Rx_buffer[8] != 0x00)
	{
		Serial.println("\nAuthentication Step one failed of Ultralight C Tag");
		return false;
	}
	
	// //If authenticated step one then
	else
	{
		//Sending Authentication 2 command
		for (int cnt1 = 0; cnt1 < sizeof(ul_auth_step2); cnt1++)
			Serial2.write(ul_auth_step2[cnt1]);
		
		//Reading Reciever's Response
		delay(100);
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial.print(Rx_buffer[counters1],HEX);
			Serial.print(" ");
			counters1++;
		}
		//Serial.println("Authentication 2");

		//Checking Authentication Step Two
		if (Rx_buffer[counters1 - 2] != 0x00)
		{
			Serial.println("\nAuthentication Step 2 failed of Ultralight C Tag");
			return false;
		}
		else
		{
			Serial.println("\nAuthenticated Ultralight C Tag");
			return true;
		}
		
	}

}
//============================= PICC UL_3DES_AUTHENTICATION ENDs   ========================


//============================= PICC ULC_READING_FUNCTION STARTS  =========================
void Reader::PCD_ULC_READ(byte blk)
{
	//Setting the Block in Reading Command
	rd_tag[8] = blk;
	
	//Setting XOR byte in Command
	XOR = 0x00;
	for (int cnt1 = 4; cnt1 < 9; cnt1++)
		XOR = XOR^rd_tag[cnt1];
	rd_tag[9] = XOR;

	//Sending Command To reader
	for (int cnt1 = 0; cnt1 < 10; cnt1++)
		Serial2.write(rd_tag[cnt1]);
	
	//Receiving Data from Reader
	delay(100);
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.write(Rx_buffer[counters1]);
		Serial.print(" ");
		counters1++;
	}
	Serial.print("\n\n");
	//Writing Values to  User defined Variable
	//for (int cnt1 = 0; cnt1 < len; cnt1++)
	//	ptr[cnt1] = Rx_buffer[cnt1+8];

}
//============================= PICC ULC_READING_FUNCTION ENDS ============================
void Reader::PCD_ULC_READs(byte blk)
{
	//Setting the Block in Reading Command
	rd_tag[8] = blk;
	
	//Setting XOR byte in Command
	XOR = 0x00;
	for (int cnt1 = 4; cnt1 < 9; cnt1++)
		XOR = XOR^rd_tag[cnt1];
	rd_tag[9] = XOR;

	//Sending Command To reader
	for (int cnt1 = 0; cnt1 < 10; cnt1++)
		Serial2.write(rd_tag[cnt1]);
	
	//Receiving Data from Reader
	delay(100);
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.write(Rx_buffer[counters1]);
		Serial.print(" ");
		counters1++;
	}
	Serial.print("\n\n");
	//Writing Values to  User defined Variable
	//for (int cnt1 = 0; cnt1 < len; cnt1++)
	//	ptr[cnt1] = Rx_buffer[cnt1+8];

}
//============================= PICC ULC_READING_FUNCTION ENDS ============================


//============================= PICC ULC_WRITING_FUNCTION STARTS  =========================
void Reader::PCD_ULC_WRITE(byte blk, byte *ptr)
{
	//Setting Block in Command
	write_tag[8] = blk;

	//Data written on Command
	for (int cnt1 = 0; cnt1 < 3; cnt1++)
		write_tag[cnt1 + 9] = ptr[cnt1];

	//XOR Calculation
	XOR = 0x00;
	for (int cnt1 = 4; cnt1 < sizeof(write_tag)-1; cnt1++)
		XOR = XOR^write_tag[cnt1];

	//Sending Command To Reader
	for (int cnt1 = 0; cnt1 < sizeof(write_tag); cnt1++)
		Serial2.write(write_tag[cnt1]);

	//recieving Reader's Response
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		counters1++;
	}

	//Checking Whether Wrote or Not
	if (Rx_buffer[8] == 0x00)
	{
		Serial.println("\nWritten Successfully");
		return;
	}
	else
	{
		Serial.println("\nSome Issues When writing to TAG");
		return;
	}
}
//============================= PICC ULC_WRITING_FUNCTION ENDS ============================


//============================= READ AUTHENTICATION MODE ==================================
void Reader::PICC_READ_ULC_AUTH()
{
	//Send Authentication Command
	for (int cnt1 = 0; cnt1 < sizeof(rd_auth_md); cnt1++)
		Serial2.write(rd_auth_md[cnt1]);

	//Reading Reciever's Response
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		counters1++;
	}
	//See Reader's response on Console
	for (int cnt1 = 0; cnt1 < counters1; cnt1++)
	{
		Serial.print(Rx_buffer[counters1], HEX);
		Serial.print(" ");
	}
	Serial.println();
}
//============================= READ AUTHENTICATION MODE ==================================


//============================= SET AUTHENTICATION MODE  ==================================
void Reader::PICC_SET_AUTH_MD()
{
	//Send Set Authentication Mode 1 Command
	for (int cnt1 = 0; cnt1 < sizeof(st_ulauth_md1); cnt1++)
		Serial2.write(st_ulauth_md1[cnt1]);

	//Read Reader's Response
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial2.print(Rx_buffer[counters1],HEX);
		counters1++;
	}

	//Send Authentication Mode 2 Command
	for (int cnt1 = 0; cnt1 < sizeof(st_ulauth_md2); cnt1++)
		Serial2.write(st_ulauth_md2[cnt1]);

	//Read Reader's Response
	counters1 = 0;
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial2.print(Rx_buffer[counters1],HEX);
		counters1++;
	}
}
//============================= SET AUTHENTICATION MODE  ==================================


//============================= SET 3DES KEY ON ULC TAG/CARD START ========================
bool Reader::PCD_WRITE_3DES_ULC(byte *ptr, size_t len)
{
	if (len != 16)
		return 0;

	else
	{
		
//*****************************************************************************************		
		//Setting First 4 bytes of KEY to commands A
		for (int cnt1 = 0; cnt1 < 4; cnt1++)
			write_auth_key2[cnt1 + 9] = ptr[3-cnt1];
		//Set XOR of Command A
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(write_auth_key2)-1; cnt1++)
			XOR = XOR^write_auth_key2[cnt1];
		write_auth_key2[13] = XOR;


		//Setting First 4 bytes of KEY to commands B
		for (int cnt1 = 0; cnt1 < 4; cnt1++)
			write_auth_key1[cnt1 + 9] = ptr[7 - cnt1];
		//Set XOR of Command B
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(write_auth_key1)-1; cnt1++)
			XOR = XOR^write_auth_key1[cnt1];
		write_auth_key1[13] = XOR;

		//Setting First 4 bytes of KEY to commands C
		for (int cnt1 = 0; cnt1 < 4; cnt1++)
			write_auth_key4[cnt1 + 9] = ptr[15 - cnt1];
		//Set XOR of Command C
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(write_auth_key4)-1; cnt1++)
			XOR = XOR^write_auth_key4[cnt1];
		write_auth_key4[13] = XOR;

		//Setting First 4 bytes of KEY to commands D
		for (int cnt1 = 0; cnt1 < 4; cnt1++)
			write_auth_key3[cnt1 + 9] = ptr[11 - cnt1];
		//Set XOR of Command D
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(write_auth_key3)-1; cnt1++)
			XOR = XOR^write_auth_key3[cnt1];
		write_auth_key3[13] = XOR;
//*****************************************************************************************

		//Sending Command 1 To Reader from MCU HOST
		for (int cnt1 = 0; cnt1 < sizeof(write_auth_key1); cnt1++)
			Serial2.write(write_auth_key1[cnt1]);
		//Reading Reciver Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}

		//Sending Command 2 To Reader from MCU HOST
		for (int cnt1 = 0; cnt1 < sizeof(write_auth_key2); cnt1++)
			Serial2.write(write_auth_key2[cnt1]);
		//Reading Reciver Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}

		//Sending Command 3 To Reader from MCU HOST
		for (int cnt1 = 0; cnt1 < sizeof(write_auth_key3); cnt1++)
			Serial2.write(write_auth_key3[cnt1]);
		//Reading Reciver Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}

		//Sending Command 4 To Reader from MCU HOST
		for (int cnt1 = 0; cnt1 < sizeof(write_auth_key4); cnt1++)
			Serial2.write(write_auth_key4[cnt1]);
		//Reading Reciver Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}
//*****************************************************************************************
		return 1;
	}
}
//============================= SET 3DES KEY ON ULC TAG/CARD ENDS  ========================

/************ ULTRALIGHT 3DES Authentication/Reading/Writing Functions *******************
********************************* ENDS HERE ***********************************************
******************************************************************************************/



/************ Mifare classic   Authentication/Reading/Writing Functions *******************
* Immediate Key Setting To The Reader
* Save Key To the Block
* Load Key from block If not Using Immediate Key
******************************************************************************************/
//============================= STORE KEY ON EEPROM of READER =============================
bool Reader::PCD_WRITE_KEY_EEPROM(byte *Key, size_t len, byte Gn)
{
	if ((len != 0x06) || (Gn>0x31))
		return false;

	else
	{
		//Setting Command byte array of EEPROM 
		for (int cnt1 = 10; cnt1 < 16; cnt1++)
			mf_stkey[cnt1] = Key[cnt1 - 10];
		mf_stkey[9] = Gn;
		
		//Setting XOR byte
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(mf_stkey)-1; cnt1++)
			XOR = XOR^mf_stkey[cnt1];

		mf_stkey[sizeof(mf_stkey) - 1] = XOR; 

		//Sending the command to reader for Writing KEY to Reader's EEPROM
		for (int cnt1 = 0; cnt1 < sizeof(mf_stkey); cnt1++)
			Serial2.write(mf_stkey[cnt1]);

		//Getting Reader's Response
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			counters1++;
		}
		return true;
	}
}
//============================= STORE KEY ON EEPROM of READER ENDS  ========================


//============================= MIFARE AUTHENTICATE Number 1 (USING EEPROM KEY) ============
bool Reader::PICC_AUTH_1(byte md, byte blk, byte Gn)
{
	if ((md != 0x60) || (md != 0x61) || (Gn > 0x31) || (blk > 0x3F))
		return false;
	
	else
	{
		//Settings Authenticate 1 Command
		mf_auth1[8] = md;
		mf_auth1[9] = blk;
		mf_auth1[10] = Gn;

		//Setting XOR value
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(mf_auth1)-1; cnt1++)
			XOR = XOR^mf_auth1[cnt1];
		mf_auth1[sizeof(mf_auth1)-1] = XOR;

		//Sending Mifare_Authentication 1 Comnmand To Reader
		for (int cnt1 = 0; cnt1 < sizeof(mf_auth1); cnt1++)
			Serial2.write(mf_auth1[cnt1]);

		//Getting Reader's Response after sending Reader's Command
		counters1 = 0;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial.print(Rx_buffer[counters1], HEX); //Sending Recieved Data to Console
			Serial.print(" ");
			counters1++;
		}
		return true;
	}
}
//============================= MIFARE AUTHENTICATE Number 1 (USING EEPROM KEY) ============


//============================= MIFARE AUTHENTICATE Number 2 (Provide KEY in CMD) ==========
bool Reader::PICC_AUTH_2(byte md, byte blk, byte *ptr, size_t len)
{
	if ((len != 0x06) || (md != 0x60) || (md!=0x61))
	{
		Serial.println("Length of Key Must be 6 bytes");//Display Data on Serial Console
		return 0;
	}

	else
	{
		//Setting the Command for Sending Mifare Authentication 2
		for (int cnt1 = 0; cnt1 < 6; cnt1++)
		{
			mf_auth2[cnt1 + 10] = ptr[cnt1];
		}
		mf_auth2[9] = blk;
		mf_auth2[8] = md;

		//Calculating XOR command
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(mf_auth2)-1; cnt1++)
			XOR = XOR^mf_auth2[cnt1];
		mf_auth2[sizeof(mf_auth2)-1] = XOR;

		//Sending Command To Reader from HOST
		for (int cnt1 = 0; cnt1 < sizeof(mf_auth2); cnt1++)
			Serial2.write(mf_auth2[cnt1]);
		
		//Getting Reader's Response
		counters1 = 0x00;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial2.print(Rx_buffer[counters1], HEX);
			counters1++;
		}

		return 1;
	}
}
//============================= MIFARE AUTHENTICATE Number 2 (Provide KEY in CMD) ==========


//============================= MIFARE AUTHENTICATE Number 3 (Provide KEY in CMD) ==========
bool PICC_AUTH_3(byte md, byte blk, byte *ptr, size_t len)
{
	if ((len != 0x06) || (md != 0x60) || (md != 0x61))
	{
		Serial.println("Length of Key Must be 6 bytes");//Display Data on Serial Console
		return 0;
	}

	else
	{
		//Setting Command Byte for Mifare Authentication 3 for 7 byte UID CMD:0x0225
		for (int cnt1 = 0; cnt1 < 6; cnt1++)
			mf_auth3[cnt1 + 10] = ptr[cnt1];
		mf_auth3[9] = blk;	//Address of the Block for Authentication
		mf_auth3[8] = md;

		//Calculating XOR command
		XOR = 0x00;
		for (int cnt1 = 4; cnt1 < sizeof(mf_auth3)-1; cnt1++)
			XOR = XOR^mf_auth3[cnt1];
		mf_auth3[sizeof(mf_auth3)-1] = XOR;

		//Sending Command To Reader from HOST
		for (int cnt1 = 0; cnt1 < sizeof(mf_auth3); cnt1++)
			Serial2.write(mf_auth3[cnt1]);

		//Getting Reader's Response
		counters1 = 0x00;
		while (Serial2.available()>0)
		{
			Rx_buffer[counters1] = Serial2.read();
			Serial2.print(Rx_buffer[counters1], HEX);
			counters1++;
		}

		return 1;
	}
}
//============================= MIFARE AUTHENTICATE Number 2 (Provide KEY in CMD) ==========


//============================= PICC HALT A FUNCTION START =================================
void Reader::PCD_HALTA()
{
	//Sedning HALTA Command to Reader
	for (int cnt1 = 0; cnt1 < sizeof(halta); cnt1++)
		Serial2.write(halta[cnt1]);

	//Recieving Reader's Resposnse
	counters1 = 0;
	delay(10);
	while (Serial2.available()>0)
	{
		Rx_buffer[counters1] = Serial2.read();
		Serial.print(Rx_buffer[counters1],HEX);
		Serial.print(" ");
		counters1++;
	}
	Serial.println();
	//Check Reader's response
	if (Rx_buffer[8] == 0x00)
		return;
	else
		Serial.println("Error While HALTING");
}
//============================= PICC HALT A FUNCTION ENDS ==================================
