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

//---------------------------------------------------------------------------
#ifndef frmMainUH
#define frmMainUH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.Grids.hpp>
#include <Vcl.ExtCtrls.hpp>
//---------------------------------------------------------------------------
#include "EmulatorDecipherU.h"
#include <Vcl.Imaging.jpeg.hpp>
//---------------------------------------------------------------------------

class TfrmMain : public TForm
{
__published:	// IDE-managed Components
    TButton *btnLoadAsm;
    TMemo *memoOutput;
    TMemo *SourceContent;
    TStringGrid *DebInsn;
    TStringGrid *RegDump;
    TButton *btnRun;
    TButton *btnStop;
    TButton *btnStep;
    TButton *btnGoTo;
    TEdit *editGoTo;
    TPanel *ViewPort;
    TPanel *Ball;
    TEdit *editPC;
    TLabel *Label1;
    TLabel *Label2;
    TEdit *editStack;
    TEdit *editTextEnd;
    TLabel *Label3;
    TLabel *Label6;
    TEdit *editExecBlockSize;
    TLabel *Label7;
    TEdit *editMemSize;
    TEdit *Edit2;
    TLabel *Label8;
    TLabel *Label9;
    TEdit *editTextStart;
    TTimer *TimerStep;
    TButton *btnReset;
    TEdit *editExecBlockInterval;
    TLabel *Label10;
    TEdit *editCurPC;
    TLabel *Label11;
    TEdit *editRunAt;
    TButton *btnRunAt;
    TStringGrid *DebMemory;
    TLabel *Label12;
    TEdit *editMemWatch;
    TPanel *SnowL1C1;
    TPanel *SnowL1C2;
    TPanel *SnowL1C3;
    TPanel *SnowL1C4;
    TPanel *SnowL1C5;
    TPanel *SnowL2C2;
    TPanel *SnowL2C3;
    TPanel *SnowL2C4;
    TPanel *SnowL2C5;
    TPanel *SnowL2C6;
    TPanel *SnowL2C1;
    TPanel *SnowL3C1;
    TPanel *SnowL3C2;
    TPanel *SnowL3C3;
    TPanel *SnowL3C4;
    TPanel *SnowL3C5;
    TImage *Image1;
    TTimer *SnowTimer;
    TButton *btnKeypair;
    TButton *btnCrypt;
    TLabel *Label4;
    TEdit *editRSA_P;
    TLabel *Label5;
    TEdit *editRSA_Q;
    TLabel *Label13;
    TEdit *editRSA_N;
    TEdit *editRSA_E;
    TLabel *Label14;
    TEdit *editRSA_L;
    TEdit *editRSA_D;
    TLabel *Label15;
    TLabel *Label16;
    TPanel *BallCenter;
    TLabel *Label17;
    void __fastcall btnLoadAsmClick(TObject *Sender);
    void __fastcall btnRunClick(TObject *Sender);
    void __fastcall btnStopClick(TObject *Sender);
    void __fastcall editPCKeyPress(TObject *Sender, System::WideChar &Key);
    void __fastcall TimerStepTimer(TObject *Sender);
    void __fastcall btnStepClick(TObject *Sender);
    void __fastcall btnResetClick(TObject *Sender);
    void __fastcall btnGoToClick(TObject *Sender);
    void __fastcall btnRunAtClick(TObject *Sender);
    void __fastcall SnowTimerTimer(TObject *Sender);
    void __fastcall btnCryptClick(TObject *Sender);
    void __fastcall btnKeypairClick(TObject *Sender);
private:	// User declarations

    enum ProgramState {
        stateRunning,
        stateStopping,
        stateStopped
    };

    enum Ports : int {
        portsVideo = 0x2b00
    };

    typedef struct {
        short ToBeUpdated; // +0
        short BallLeft;    // +2
        short BallTop;     // +4
    } TVideoPort;


    RiscV_RV32I     FRiscV_CPU;     // CPU
    ProgramState    FState;         // RISC-V program running state
    char           *FpDebuggerMem;  // Memory for debugger comparison (same of RISC-V)
    char           *FpRiscVMem;     // Memory for RISC-V processor (ROM + RAM)
    int             FcRiscVMem;     // Memory size
    unsigned long   FBreakpoint;    // Breakpoint set by "Run At" button

    int     ConvertToInt     (String AHex);
    String  ConvertToString  (long AValue);
    __int64 ConvertToInt64   (String AHex);
    String  ConvertToString64(__int64 AValue);
    void    RefreshDebug();
    void    RedrawMemory();
    void    RedrawMemoryRow(int ARow);
    void    UpdateVideo(TVideoPort *ANewValues);

    unsigned __int64 Hlp_EncryptOpCode(TinyRSA &ACipher, unsigned long APlainOpCode, char *AiMem, int AiOffset);

    void    Run();

    __property char *RiscVMem = { read = FpRiscVMem };


    // Snow effect
    DynamicArray<TPanel *>FSnowBallsL1; // Parallactic Level 1 (near)
    DynamicArray<TPanel *>FSnowBallsL2;
    DynamicArray<TPanel *>FSnowBallsL3; // Parallactic Level 3 (far)

    void InitSnowballs();

public:		// User declarations
    __fastcall TfrmMain(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TfrmMain *frmMain;
//---------------------------------------------------------------------------
#endif
