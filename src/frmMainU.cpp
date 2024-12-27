/*
    RISC-V ciphered app
    Copyright (C) 2024  Daniele Giovanardi   daniele.giovanardi@madenetwork.it

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
On a Debian-based Linux distribution install Clang:
sudo apt install -y clang

Then compile ball.c with Clang:
clang --target=riscv32 -march=rv32i -static -S -fno-addrsig ball.c


DON'T FORGET TO CUT THE FOLLOWING LINES FROM ball.s (in .text section):
	.attribute	4, 16
	.attribute	5, "rv32i2p0"


             /////////////////////////////////////////////////////////////////////////////
            // WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! //
           //                                                                         //
          //           RSA encoded app takes 64 bits for op. codes then              //
         //                      text segment MUST BE doubled                       //
        //              and data segment MUST BE moved 4 KB forward                //
       //               so take care to set the following parameter               //
      //                  (it differs from original repository!)                 //
     //                                                                         //
    //                  PS: Also ball.c differs from original repo             //
   //                                                                         //
  //                  ROM (rwx) : ORIGIN = 0x00000000, LENGTH = 0x02000      //
 //                   RAM (rwx) : ORIGIN = 0x00002000, LENGTH = 0x01000     //
/////////////////////////////////////////////////////////////////////////////

Parameters for assembler compiler:
(https://riscvasm.lucasteske.dev/#)

__heap_size   = 0x200;
__stack_size  = 0x800;

MEMORY
{
  ROM (rwx) : ORIGIN = 0x00000000, LENGTH = 0x02000
  RAM (rwx) : ORIGIN = 0x00002000, LENGTH = 0x01000
}


Parameters for (this) debugger:
  - set memory size to 3000 (hex)
  - set program counter to 0
  - set stack pointer to 2A40 where:
                         2000h (RAM origin)
                       +   40h (variables)
                       +  200h (heap size)
                       +  800h (stack size)


Video controller port:
 - 0x2b00 (short)   If not 0 => Ball pos to be updated
 - 0x2b02 (short)   Ball left position
 - 0x2b04 (short)   Ball top position
*/

//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
#include <System.StrUtils.hpp>

#include "frmMainU.h"
#include "TinyRSAU.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TfrmMain *frmMain;
//---------------------------------------------------------------------------

__fastcall TfrmMain::TfrmMain(TComponent* Owner)
    : TForm(Owner)
{
char *RegNames[] =
{
        "zero",
        "ra",
        "sp",
        "gp",
        "tp",
        "t0", "t1", "t2",
        "s0",
        "s1",
        "a0", "a1",
        "a2", "a3", "a4", "a5", "a6", "a7",
        "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
        "t3", "t4", "t5", "t6"
};

    Randomize();

    InitSnowballs();

    // Registers StringGrid setup
    RegDump->RowCount     = 32;
    RegDump->ColCount     = 2;
    RegDump->ColWidths[0] = 32;
    RegDump->ColWidths[1] = 112;

    for (unsigned long c=0; c<sizeof(RegNames)/sizeof(RegNames[0]); c++)
        RegDump->Cells[0][c] = RegNames[c];

    // Debugger instructions StringGrid setup
    DebInsn->FixedRows = 1;
    DebInsn->RowCount  = 2;
    DebInsn->ColCount  = 5;
    DebInsn->ColWidths[0]= 40;
    DebInsn->ColWidths[1]= 75;
    DebInsn->ColWidths[2]= 120;
    DebInsn->ColWidths[3]= 60;
    DebInsn->ColWidths[4]= 2000;
    DebInsn->Cells[0][0] = "Offset";
    DebInsn->Cells[1][0] = "Clear OpCode";
    DebInsn->Cells[2][0] = "Encrypted OpCode";
    DebInsn->Cells[3][0] = "Mnemonic";
    DebInsn->Cells[4][0] = "Parameters";

    // Debugger memory StringGrid setup
    DebMemory->ColCount = 1;
    DebMemory->ColWidths[0]= 2000;

    // Init vars
    FpDebuggerMem = NULL;
    FpRiscVMem = NULL;
    FcRiscVMem = 0;
    FState     = stateStopped;
}
//---------------------------------------------------------------------------

int TfrmMain::ConvertToInt(String AHex)
{
long Value;
char *pValue = (char *)&Value;

    if (AHex.Length() > 8)
        throw Exception("Value overflow");

    AHex = String::StringOfChar('0', 8-AHex.Length()) + AHex;
    HexToBin(AHex.SubString(7,2).c_str(), pValue  , 1);
    HexToBin(AHex.SubString(5,2).c_str(), pValue+1, 1);
    HexToBin(AHex.SubString(3,2).c_str(), pValue+2, 1);
    HexToBin(AHex.SubString(1,2).c_str(), pValue+3, 1);

    return Value;
}
//---------------------------------------------------------------------------

String TfrmMain::ConvertToString(long AValue)
{
union {
    long Value;
    struct {
        char First;
        char Second;
        char Third;
        char Fourth;
    } Byte;
} strValue;

String   Hex;
wchar_t *pHex;


    strValue.Value = AValue;
    Hex.SetLength(8);
    pHex = Hex.c_str();

    BinToHex(&strValue.Byte.Fourth,  pHex   , 1);
    BinToHex(&strValue.Byte.Third , &pHex[2], 1);
    BinToHex(&strValue.Byte.Second, &pHex[4], 1);
    BinToHex(&strValue.Byte.First , &pHex[6], 1);

    return Hex;
}
//---------------------------------------------------------------------------

__int64 TfrmMain::ConvertToInt64(String AHex)
{
__int64 Value;
char   *pValue = (char *)&Value;

    if (AHex.Length() > 16)
        throw Exception("Value overflow");

    AHex = String::StringOfChar('0', 16-AHex.Length()) + AHex;
    HexToBin(AHex.SubString(15,2).c_str(), pValue  , 1);
    HexToBin(AHex.SubString(13,2).c_str(), pValue+1, 1);
    HexToBin(AHex.SubString(11,2).c_str(), pValue+2, 1);
    HexToBin(AHex.SubString(9,2).c_str() , pValue+3, 1);
    HexToBin(AHex.SubString(7,2).c_str() , pValue+4, 1);
    HexToBin(AHex.SubString(5,2).c_str() , pValue+5, 1);
    HexToBin(AHex.SubString(3,2).c_str() , pValue+6, 1);
    HexToBin(AHex.SubString(1,2).c_str() , pValue+7, 1);

    return Value;
}
//---------------------------------------------------------------------------

String TfrmMain::ConvertToString64(__int64 AValue)
{
union {
    __int64 Value;
    struct {
        char First;
        char Second;
        char Third;
        char Fourth;
        char Fiveth;
        char Sixth;
        char Seventh;
        char Eighth;
    } Byte;
} strValue;

String   Hex;
wchar_t *pHex;


    strValue.Value = AValue;
    Hex.SetLength(16);
    pHex = Hex.c_str();

    BinToHex(&strValue.Byte.Eighth,  pHex    , 1);
    BinToHex(&strValue.Byte.Seventh,&pHex[2] , 1);
    BinToHex(&strValue.Byte.Sixth , &pHex[4] , 1);
    BinToHex(&strValue.Byte.Fiveth, &pHex[6] , 1);
    BinToHex(&strValue.Byte.Fourth, &pHex[8] , 1);
    BinToHex(&strValue.Byte.Third , &pHex[10], 1);
    BinToHex(&strValue.Byte.Second, &pHex[12], 1);
    BinToHex(&strValue.Byte.First , &pHex[14], 1);

    return Hex;
}
//---------------------------------------------------------------------------

void TfrmMain::RefreshDebug()
{
TGridRect DebuggerRow;

    DebuggerRow.Left  = 0;
    DebuggerRow.Right = DebInsn->ColCount-1;

    // Registers
    for (int c=0; c<=RiscV::t6; c++)
        RegDump->Cells[1][c] = ConvertToString(FRiscV_CPU.Registers[c]);

    // PC
    editCurPC->Text = ConvertToString(FRiscV_CPU.PC);

    // Program line
    for (int c=1; c<=DebInsn->RowCount; c++) // Bypass header
        if (DebInsn->Objects[0][c] == (TObject *)FRiscV_CPU.PC)
        {
            DebuggerRow.Top    =
            DebuggerRow.Bottom = c;
            DebInsn->Selection = DebuggerRow;

            // Scroll grid if selected row is not visible
            if (c < DebInsn->TopRow
                || c > DebInsn->TopRow + DebInsn->VisibleRowCount)
                    DebInsn->TopRow = c;
            break;
        }

    // Memory
    for (int c=0; c<(FcRiscVMem/16); c++)
        if (memcmp(FpDebuggerMem+(c*16), FpRiscVMem+(c*16), 16)) {
            memcpy(FpDebuggerMem+(c*16), FpRiscVMem+(c*16), 16);
            RedrawMemoryRow(c);
        }

    // Memory - Last line
    if ((FcRiscVMem%16)
        && memcmp( FpDebuggerMem+((FcRiscVMem/16)*16), FpRiscVMem+((FcRiscVMem/16)*16), (FcRiscVMem%16) )) {
            memcpy( FpDebuggerMem+((FcRiscVMem/16)*16), FpRiscVMem+((FcRiscVMem/16)*16), (FcRiscVMem%16) );
            RedrawMemoryRow((FcRiscVMem/16)+1);
    }
}
//---------------------------------------------------------------------------

void TfrmMain::RedrawMemory()
{
TGridRect SelectedRow;

    // Set StringGrid RowCount
    DebMemory->RowCount = (FcRiscVMem/16) + ((FcRiscVMem%16) ? 1 : 0);
    for(int cRow=0; cRow<DebMemory->RowCount; cRow++)
        RedrawMemoryRow(cRow);

    // Select first line
    SelectedRow.Left     = 0;
    SelectedRow.Right    = DebMemory->ColCount-1;
    SelectedRow.Top      = 0;
    SelectedRow.Bottom   = 0;
    DebMemory->Selection = SelectedRow;
    DebMemory->TopRow    = 0;
}
//---------------------------------------------------------------------------

void TfrmMain::RedrawMemoryRow(int ARow)
{
String HexLine, HexByte, Ascii;
char   CurrentByte;
int    cChar;
int    cCharOnRow;

    // Calculate chars in row
    if (ARow == DebMemory->RowCount-1)
        cCharOnRow = (FcRiscVMem%16) ? FcRiscVMem%16 : 16;
    else
        cCharOnRow = 16;

    // Create line
    HexLine = "";
    HexByte.SetLength(2);
    Ascii.SetLength(cCharOnRow);
    for(cChar=0; cChar<cCharOnRow; cChar++) {
        CurrentByte = FpDebuggerMem[ARow*16 + cChar];
        BinToHex(&CurrentByte, HexByte.c_str(), 1);
        HexLine = HexLine + HexByte + String::StringOfChar( (cChar==7) ? '-' : ' ', 1 );
        Ascii[cChar+1] = (CurrentByte < ' ' || CurrentByte > '~') ? '.' : CurrentByte;
    }
    HexLine = HexLine + String::StringOfChar( ' ', 3*(16-cCharOnRow) );
    DebMemory->Cells[0][ARow] = ConvertToString(ARow*16) + ": " + HexLine + "; " + Ascii;
}
//---------------------------------------------------------------------------

void TfrmMain::UpdateVideo(TVideoPort *ANewValues)
{
    // New positions
    Ball->Left  = ANewValues->BallLeft;
    Ball->Top   = ANewValues->BallTop;

    Randomize();
    BallCenter->Color = (TColor)Random(0xffffff);

    ANewValues->ToBeUpdated = 0; // Flag reset

    memoOutput->Lines->Add(Now().FormatString("hh:nn:ss,zzz") + " - Graph. update - "
        "Ball left: " + Ball->Left + ", "
        "Ball top: "  + Ball->Top
    );

    Application->ProcessMessages(); // Run process message pump to refresh window
}
//---------------------------------------------------------------------------



//---------------------------------------------------------------------------
// Form events
//---------------------------------------------------------------------------

void __fastcall TfrmMain::editPCKeyPress(TObject *Sender, System::WideChar &Key)
{
    if (Key >= ' ' && (Key < '0' || Key > '9') && (Key < 'a' || Key > 'f') && (Key < 'A' || Key > 'F'))
        Key = 0;
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnLoadAsmClick(TObject *Sender)
{
    throw Exception("Don't use this button. After set assembler text please click \"Step 2 => Encode .text segment\"");
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnStopClick(TObject *Sender)
{
    btnStop->Enabled = false;
    FState = stateStopping;
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnRunClick(TObject *Sender)
{
    FBreakpoint       = (unsigned long)-1;
    DebMemory->TopRow = ConvertToInt(editMemWatch->Text)/16; // Memory watch address visible only on Run (button)
    Run();
}
//---------------------------------------------------------------------------

void TfrmMain::Run()
{
    if (!FpRiscVMem || !FcRiscVMem)
        throw Exception("Program not loaded");

    btnRun  ->Enabled = false;
    btnStop ->Enabled = true;
    btnRunAt->Enabled = false;
    btnGoTo ->Enabled = false;
    btnStep ->Enabled = false;
    btnReset->Enabled = false;
    btnLoadAsm->Enabled = false;

    FState = stateRunning;

    TimerStep->Interval = editExecBlockInterval->Text.ToInt();
    TimerStep->Enabled  = true; // Start execution
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::TimerStepTimer(TObject *Sender)
{
String ExceptionMessage;

    // Stop timer to execute entire block
    TimerStep->Enabled = false;
    Application->ProcessMessages(); // Needed to stop the timer

    // Execute block
    try
    {
        for (int c=0; c<editExecBlockSize->Text.ToInt(); c++) {
            if (FRiscV_CPU.PC == FBreakpoint) // If breakpoint set => request stop
                FState = stateStopping;
            else
                btnStepClick(TimerStep);
        }
    }
    catch(Exception &e)
    {
        FState = stateStopping;
        ExceptionMessage = e.Message;
    }

    // Refresh debug grids
    RefreshDebug();

    // Show exception (if raised) or take action by execution state
    if (!ExceptionMessage.IsEmpty())
        ShowMessage(ExceptionMessage);
    else if (FState == stateRunning)
        TimerStep->Enabled = true;      // Restart timer
    else if (FState == stateStopping) {
            btnRun  ->Enabled = true;
            btnStop ->Enabled = false;
            btnRunAt->Enabled = true;
            btnGoTo ->Enabled = true;
            btnStep ->Enabled = true;
            btnReset->Enabled = true;
            btnLoadAsm->Enabled = true;

            FState = stateStopped;

            RefreshDebug();

            // On exit process message pump will refresh window
    }
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnStepClick(TObject *Sender)
{
String      ExceptionMessage;
TVideoPort *pVideoPort = (TVideoPort *)(RiscVMem+portsVideo);

    // Asserts
    if (!FpRiscVMem || !FcRiscVMem)
        throw Exception("Program not loaded");

    if (FRiscV_CPU.PC >= (unsigned long)ConvertToInt(editTextEnd->Text))
        throw Exception("Segmentation fault");

    try
    {
        FRiscV_CPU.Step();

        // Update graphics if flag set
        if (pVideoPort->ToBeUpdated)
            UpdateVideo(pVideoPort);
    }
    catch(Exception &e)
    {
        if (FState == stateStopped)
            ExceptionMessage = e.Message;
        else
            throw Exception(e.Message);
    }

    // If tracing refresh debugger
    if (FState == stateStopped)
        RefreshDebug();

    // Show exception (if raised and program is not running)
    if(!ExceptionMessage.IsEmpty())
        ShowMessage(ExceptionMessage);
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnResetClick(TObject *Sender)
{
TGridRect DebuggerRow;

    if (!FpRiscVMem || !FcRiscVMem)
        throw Exception("Program not loaded");

    FRiscV_CPU.Reset(
        ConvertToInt(editPC->Text),     // InitialPC
        ConvertToInt(editStack->Text)   // StackPointer
    );

    RefreshDebug();

    // Better select & show first debugger line
    DebuggerRow.Left   = 0;
    DebuggerRow.Right  = DebInsn->ColCount-1;
    DebuggerRow.Top    = 1;
    DebuggerRow.Bottom = 1;
    DebInsn->Selection = DebuggerRow;
    DebInsn->TopRow    = 1;

    editCurPC->Clear();
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnRunAtClick(TObject *Sender)
{
    if (!editRunAt->Text.Trim().IsEmpty()) {
        FBreakpoint = ConvertToInt(editRunAt->Text);
        Run();
    }
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnGoToClick(TObject *Sender)
{
int NewPC;

    if (!editGoTo->Text.Trim().IsEmpty()) {
        if (!FpRiscVMem || !FcRiscVMem)
            throw Exception("Program not loaded");

        if (NewPC&1)
            throw Exception("Program counter is odd");

        NewPC = ConvertToInt(editGoTo->Text);
        FRiscV_CPU.GoTo(NewPC);
        RefreshDebug();
    }
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnKeypairClick(TObject *Sender)
{
    Application->MessageBox(
        L"WARNING!\r\n\r\nDon't use TinyRSA algorithm in production environment!\r\n\r\n"
        L"Code is provided for conceptual purpose only",
        L"RSA usage warning",
        MB_ICONWARNING|MB_OK
    );

    FRiscV_CPU.Decipher.GenerateKeyPair();

    editRSA_N->Text = ConvertToString64( FRiscV_CPU.Decipher.N );
    editRSA_E->Text = ConvertToString  ( FRiscV_CPU.Decipher.E );
#ifdef TINYRSA_PRIVATE_EXPOSURE
    editRSA_P->Text = ConvertToString  ( FRiscV_CPU.Decipher.P );
    editRSA_Q->Text = ConvertToString  ( FRiscV_CPU.Decipher.Q );
    editRSA_L->Text = ConvertToString64( FRiscV_CPU.Decipher.LambdaN );
    editRSA_D->Text = ConvertToString64( FRiscV_CPU.Decipher.D );
#else
    editRSA_P->Text = "Not exposed";
    editRSA_Q->Text = "Not exposed";
    editRSA_L->Text = "Not exposed";
    editRSA_D->Text = "Not exposed";
#endif

    btnKeypair->Enabled = false;
    btnCrypt  ->Enabled = true;
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::btnCryptClick(TObject *Sender)
{
TStrings       *Assembler     = SourceContent->Lines; // Assembly content
bool            Parse         = false, // Get the assembly code starting from the following line
                FirstRowEmpty = true,  // Debugger StringGrid first line not set yet (StringGrid cannot have RowCount == 0)
                FirstInsn     = false; // First instruction detected => assume address is .text segment start
int             c,                     // Generic counter
                iOffset;               // Offset to write current parsed insn in .text segment
TStringDynArray Atoms;                 // Array of exploded current line (offset + 32-bits insn + mnemonic operation + params
UnicodeString   Line,                  // Current line under parsing (with no tabs)
                Trimmed,               // Current line without multiple spaces between atoms
                hexInstruction,        // Hex-coded 32-bits instruction extracted from atoms (2nd atom)
                hexOffset;             // Hex-coded offset extracted from atoms (1st atom)
unsigned long   TextSegmentStart = 0,  // Boundary of .text segment (CPU view!)
                TextSegmentEnd   = 0;
TinyRSA         Cipher;                // RSA encoder for OpCodes
unsigned __int64 EncryptedOpCode;      // 64-bits RSA encrypted OpCode


    // Set RSA public key (N+E)
    Cipher.N = ConvertToInt64(editRSA_N->Text);
    Cipher.E = (unsigned short)ConvertToInt(editRSA_E->Text);

    // (Re)Allocate memory for new program
    if (FpRiscVMem)
        delete [] FpRiscVMem;
    FcRiscVMem = 0;
    FpRiscVMem = new char[ConvertToInt(editMemSize->Text)];
    FcRiscVMem = ConvertToInt(editMemSize->Text);
    memset(FpRiscVMem, 0, FcRiscVMem);

    // (Re)Allocate debugger comparison memory
    if (FpDebuggerMem)
        delete [] FpDebuggerMem;
    FpDebuggerMem = new char[FcRiscVMem];
    memset(FpDebuggerMem, 0, FcRiscVMem);

    // Reset .text info displayed
    editTextStart->Clear();
    editTextEnd  ->Clear();

    // Assembler output parsing
    DebInsn->RowCount = 2; // Value 1 destroys titles (i.e. FixedRows)
    for (c=0; c<Assembler->Count; c++) {
        if (Assembler->Strings[c] == "Disassembly of section .text:")
            Parse = true;    // .text found => get the assembly code
        else if (Assembler->Strings[c].Pos("Disassembly of section ") == 1 && Parse)
            break;           // .text parsed so exit
        else if (Parse) {
            Trimmed = "";    // Trim all (double) spaces
            Line = StringReplace(Assembler->Strings[c].Trim(), "\t", " ", TReplaceFlags() << rfReplaceAll);
            for (int offset=1; offset<=Line.Length(); offset++)
                if (Line[offset] != ' ')
                    Trimmed = Trimmed + UnicodeString::StringOfChar(Line[offset], 1);
                else if( Trimmed.Length() && Trimmed[Trimmed.Length()] != ' ')
                    Trimmed = Trimmed + UnicodeString::StringOfChar(' ', 1);

            // StringGrid RowCount "patch"
            if (FirstRowEmpty)
                FirstRowEmpty = false;
            else
                DebInsn->RowCount = DebInsn->RowCount + 1;

            // Parse
            Atoms = SplitString(Trimmed, " ");
            if (Atoms.Length >= 3 && Atoms[1].Length() == 8) {       // Parse only lines with this triplet: offset + hex insn + mnemonic insn

                // Code offset (to fill .text segment and for debugger line sync)
                hexOffset = Atoms[0].SubString(1, Atoms[0].Length()-1); // Cut ':' on last char
                iOffset = ConvertToInt(hexOffset.c_str());
                DebInsn->Objects[0][DebInsn->RowCount-1] = (TObject *)iOffset;

                // .text segment boundary
                if (FirstInsn) {
                    TextSegmentStart = iOffset;
                    FirstInsn = true;
                }
                TextSegmentEnd = iOffset + sizeof(long);


                // Fill encrypted .text
                EncryptedOpCode = Hlp_EncryptOpCode(Cipher, ConvertToInt(Atoms[1]), FpRiscVMem, iOffset);


                // Debugger instructions info
                DebInsn->Cells[0][DebInsn->RowCount-1] = Atoms[0]; // Code offset
                DebInsn->Cells[1][DebInsn->RowCount-1] = Atoms[1]; // Clear insn
                DebInsn->Cells[2][DebInsn->RowCount-1] = ConvertToString64(EncryptedOpCode).LowerCase(); // Ciphered insn
                DebInsn->Cells[3][DebInsn->RowCount-1] = Atoms[2]; // Mnemonic insn
                DebInsn->Cells[4][DebInsn->RowCount-1] = "";
                if (Atoms.Length > 3)                              // [Params + comments]
                    for (int AtomOffset=3; AtomOffset<Atoms.Length; AtomOffset++)
                        DebInsn->Cells[4][DebInsn->RowCount-1] = DebInsn->Cells[4][DebInsn->RowCount-1] + " " + Atoms[AtomOffset];
            }
            else {  // Else don't parse anything and copy line content in 5th col
                DebInsn->Cells[4][DebInsn->RowCount-1] = Assembler->Strings[c];
                DebInsn->Objects[0][DebInsn->RowCount-1] = (TObject *)-1;
            }
        }
    }

    //.text info (first) update
    editTextStart->Text = ConvertToString(TextSegmentStart);
    editTextEnd  ->Text = ConvertToString(TextSegmentEnd);

    // Redraw memory StringGrid
    memcpy(FpDebuggerMem, FpRiscVMem, FcRiscVMem);
    RedrawMemory();

    // Load program (.text) into CPU memory
    // ToDo: parse and load data segment (.data)
    FRiscV_CPU.Load(
        FpRiscVMem,                       // pMemory
        FcRiscVMem,                       // cMemory
        ConvertToInt(editPC->Text),       // InitialPC
        ConvertToInt(editStack->Text),    // StackPointer
        TextSegmentStart,                 // TextSegmentStart
        TextSegmentEnd                    // TextSegmentEnd
    );

    // Disable myself
    btnCrypt->Enabled = false;

    // Enable other buttons
    btnRun  ->Enabled = true;
    btnStep ->Enabled = true;
    btnReset->Enabled = true;
    btnRunAt->Enabled = true;
    btnGoTo ->Enabled = true;

    // Reset to setup
    btnReset->Click();
}
//---------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// Assume 32-bits OpCode can be holded in a 64-bits encrypted slot
//
// Because RSA encryption function ModulusPower(OpCode, E, N) give unpredictable
// magnitude then encryption process fails if returned values > 16 bits (short)
//
unsigned __int64 TfrmMain::Hlp_EncryptOpCode(TinyRSA &ACipher, unsigned long APlainOpCode, char *AiMem, int AiOffset)
{
int                     c;         // Slice counter
unsigned long           slOpCode;  // Encrypted slice of 8-bit plain opcode slice (value could exceed 65535)
TPlainOpCodeSlices      slsPlain;  // Plain 32-bits op code sliced in 8-bits
TCryptedOpCodeSlices   *pslsCrypt; // Crypted 64-bits op code (pointer) sliced in 16-bits


    RandSeed = AiOffset;                                       // To prevent duplicated encrypted codes I add entropy by VCL pseudorandom number generator sequence
    slsPlain.OpCode = APlainOpCode ^ Random(0xffffffff);       // (i.e. use offset as nonce and takeup relative element from the sequence)
    pslsCrypt = (TCryptedOpCodeSlices *)(AiMem + AiOffset*2);  // Pointer to 64-bits encrypted OpCode

    for (c=0; c<4; c++) {
        slOpCode  = ACipher.Crypt[slsPlain.Bytes[c]];

        if (slOpCode > 65535)
            throw Exception("Encryption magnitude with this public key exceeds 16-bits value! Please close and run this program again.");

        pslsCrypt->Shorts[c] = (unsigned short)slOpCode;
    }

    return pslsCrypt->CrypedOpCode;
}
//---------------------------------------------------------------------------



//---------------------------------------------------------------------------
// Snow effect
//---------------------------------------------------------------------------

void TfrmMain::InitSnowballs()
{
int c;

    FSnowBallsL1.Length = 5;
    FSnowBallsL1[0] = SnowL1C1;
    FSnowBallsL1[1] = SnowL1C2;
    FSnowBallsL1[2] = SnowL1C3;
    FSnowBallsL1[3] = SnowL1C4;
    FSnowBallsL1[4] = SnowL1C5;

    FSnowBallsL2.Length = 6;
    FSnowBallsL2[0] = SnowL2C1;
    FSnowBallsL2[1] = SnowL2C2;
    FSnowBallsL2[2] = SnowL2C3;
    FSnowBallsL2[3] = SnowL2C4;
    FSnowBallsL2[4] = SnowL2C5;
    FSnowBallsL2[5] = SnowL2C6;

    FSnowBallsL3.Length = 5;
    FSnowBallsL3[0] = SnowL3C1;
    FSnowBallsL3[1] = SnowL3C2;
    FSnowBallsL3[2] = SnowL3C3;
    FSnowBallsL3[3] = SnowL3C4;
    FSnowBallsL3[4] = SnowL3C5;


    // Start positions
    for (c=0; c<FSnowBallsL1.Length; c++) {
        FSnowBallsL1[c]->Top = Random(ViewPort->Height);
        FSnowBallsL1[c]->Tag = (Random(3)+1) * 3; // Increment * speed (fastest as near)
    }

    for (c=0; c<FSnowBallsL2.Length; c++) {
        FSnowBallsL2[c]->Top = Random(ViewPort->Height);
        FSnowBallsL2[c]->Tag = (Random(3)+1) * 2;
    }

    for (c=0; c<FSnowBallsL3.Length; c++) {
        FSnowBallsL3[c]->Top = Random(ViewPort->Height);
        FSnowBallsL3[c]->Tag = Random(3)+1;       // Increment * speed (slowest as far)
    }
}
//---------------------------------------------------------------------------

void __fastcall TfrmMain::SnowTimerTimer(TObject *Sender)
{
int c;

    for (c=0; c<FSnowBallsL1.Length; c++)
        if (FSnowBallsL1[c]->Top >= ViewPort->Height-1) {
            FSnowBallsL1[c]->Top = 0;
            FSnowBallsL1[c]->Tag = (Random(3)+1) * 3;
        }
        else
            FSnowBallsL1[c]->Top += FSnowBallsL1[c]->Tag;

    for (c=0; c<FSnowBallsL2.Length; c++)
        if (FSnowBallsL2[c]->Top >= ViewPort->Height-1) {
            FSnowBallsL2[c]->Top = 0;
            FSnowBallsL2[c]->Tag = (Random(3)+1) * 2;
        }
        else
            FSnowBallsL2[c]->Top += FSnowBallsL2[c]->Tag;

    for (c=0; c<FSnowBallsL3.Length; c++)
        if (FSnowBallsL3[c]->Top >= ViewPort->Height-1) {
            FSnowBallsL3[c]->Top = 0;
            FSnowBallsL3[c]->Tag = Random(3)+1;
        }
        else
            FSnowBallsL3[c]->Top += FSnowBallsL3[c]->Tag;
}
//---------------------------------------------------------------------------

