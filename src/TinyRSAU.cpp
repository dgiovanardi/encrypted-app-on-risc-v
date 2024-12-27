/*
    Tiny RSA algos for RISC-V ciphered app
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

       /////////////////////////////////////////////////////////////////////////////
      // WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! //
     //                                                                         //
    //                  DON'T USE IN PRODUCTION ENVIRONMENTS                   //
   //                                                                         //
  //             Generated RSA keys are too small for production!            //
 //          Algorithms in this file are for conceptual purposes only       //
/////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop
#include "TinyRSAU.h"
//---------------------------------------------------------------------------
#pragma package(smart_init)
//---------------------------------------------------------------------------

TinyRSA::TinyRSA()
{
    FN = 0;
    FE = 0;
    FD = 0;
    FP = 0;
    FQ = 0;
    FLambdaN = 0;
}
//---------------------------------------------------------------------------

unsigned __int64 TinyRSA::GreatestCommonDivisor(unsigned __int64 A, unsigned __int64 B)
{
unsigned __int64 Divisor;

    // Start search from lowest number
    if (A < B) {
        for (Divisor=A; Divisor>0; Divisor--) {
            Application->ProcessMessages(); // Let snow in frmMain
            if ( !(A%Divisor) && !(B%Divisor) )
                return Divisor;
        }
    }
    else {
        for (Divisor=B; Divisor>0; Divisor--) {
            Application->ProcessMessages(); // Let snow in frmMain
            if ( !(B%Divisor) && !(A%Divisor) )
                return Divisor;
        }
    }

    return 1; // This line should be unreachable
}
//---------------------------------------------------------------------------

unsigned __int64 TinyRSA::LowestCommonMultiple(unsigned __int64 A, unsigned __int64 B)
{
    return (A / GreatestCommonDivisor(A, B)) * B;
}
//---------------------------------------------------------------------------

// Modular multiplicative inverse of e^?1 mod lambda(n)
unsigned __int64 TinyRSA::ModularMultiplicativeInverse(unsigned __int64 A, unsigned __int64 B)
{
unsigned __int64 X = 0,
                 Y = 1,
                 M,    // Modulus in each loop. Keep in mind A and B are swapped in even cycles
                 NewX; // Temporary new X var.

bool OddCycle = false; // (1-based) odd GCD loop flag


    // Extended Euclidean Greatest Common Divisor alg
    do {
        M = A % B;
        NewX = Y - (A/B) * X;

        // Vars swap
        Y = X;
        X = NewX;
        A = B;
        B = M;

        // Cycle odd/even flag
        OddCycle = !OddCycle;

    } while (M);

    // GCD second-last reminder must be 1
    if (A != 1)
        throw Exception("Modular inverse doesn't exists");

    // If loop ends on (1-based) odd loop then add X to Y
    if (OddCycle)
        Y += X;

    return Y;
}
//---------------------------------------------------------------------------

unsigned __int64 TinyRSA::ModulusPower(unsigned __int64 Base, unsigned __int64 Power, unsigned __int64 Mod)
{
unsigned __int64 c;
unsigned __int64 Result = 1;

    for (c=0; c<Power; c++)
        Result = (Result * Base) % Mod;

    return Result;
}
//---------------------------------------------------------------------------

bool TinyRSA::IsPrime(unsigned long Prime)
{
unsigned long Divisor;

	for (Divisor=2; Divisor<=(Prime/2); Divisor++) {
        Application->ProcessMessages();  // Let snow in frmMain
        if (!(Prime % Divisor))
            return false; // Found a divisor so isn't prime
    }

	return true;
}
//---------------------------------------------------------------------------

// To prevent maths overflow on __int64 prime should me < 256
unsigned long TinyRSA::GeneratePrime()
{
unsigned long Prime;

    do {
        Prime = Random(205) + 51;
    } while (Prime < 51 || !IsPrime(Prime));

    return Prime;
}
//---------------------------------------------------------------------------

void TinyRSA::GeneratePrimes
(
    unsigned short    E,
    unsigned long    &P,
    unsigned long    &Q,
    unsigned __int64 &N,
    unsigned __int64 &LambdaN
)
{
int Counter;

    Randomize();

	for (Counter=0; Counter<10; Counter++) {

        P = GeneratePrime();
        do {
            Q = GeneratePrime();
        } while (P == Q); // P and Q must not be equals

		N = (unsigned __int64)P * (unsigned __int64)Q;  // N = P * Q

        // Lambda(N) produce a lower value then Phi(N)
		// Remember  Phi = N - Q - P + 1;
        // because   phi(N)=(P?1)*(Q?1)  aka  phi(N)=(P*Q)?Q?P+1
        LambdaN = LowestCommonMultiple(P-1, Q-1);

        Counter++;

        Application->ProcessMessages(); // Let snow in frmMain

        if (LambdaN < 100000 // For performances reason IN THIS EXAMPLE keep LambdaN as low as possible
            && GreatestCommonDivisor(E,LambdaN) == 1)
                break;
	}

    if (Counter >= 10)
        throw Exception("Very difficult to find a prime today");
}
//---------------------------------------------------------------------------

void TinyRSA::GenerateKeyPair
(
    unsigned __int64 &N,        // Public  \---> N + E = Public Key
    unsigned short   &E,        // Public  /
    unsigned __int64 &D,        // Private ----> N + D = Private Key
    unsigned long    &P,        // KEEP private (after D it's no longer necessary)
    unsigned long    &Q,        // KEEP private (after D it's no longer necessary)
    unsigned __int64 &LambdaN   // KEEP private (after D it's no longer necessary)
)
{
    E = 17; // Typical values for N-exponent are 3, 17 and 65537
            // but in this domain 65537 is too high meanwhile 17 seems good

    for (int Trials=0; Trials<10; Trials++)
    {
        try
        {
            GeneratePrimes(E, P, Q, N, LambdaN);          // E is set, other params are in output

            D = ModularMultiplicativeInverse(E, LambdaN); // If inverse doesn't exist an exception will be raised

            if (((E*D) % LambdaN) != 1)                   // (E * D) % LambdaN must be 1, else something gone wrong
                throw Exception("Modular multiplicative inverse didn't work");

            break;                                        // If no exception raised key pair generated successfully
        }
        catch(Exception &e)
        {
            if (Trials == 9)
                throw Exception(e.Message);
        }
    }
}
//---------------------------------------------------------------------------

void TinyRSA::GenerateKeyPair()
{
    GenerateKeyPair(FN, FE, FD, FP, FQ, FLambdaN);
}
//---------------------------------------------------------------------------

unsigned long TinyRSA::getCrypt(unsigned char Plain)
{
unsigned __int64 Ciphered = ModulusPower(Plain, FE, FN);

    if (Ciphered > 0xffffffff) // unsigned long overflow
        throw Exception("Cannot crypt a plain value due to conversion overflow");

    return (unsigned long)Ciphered;
}
//---------------------------------------------------------------------------

unsigned char TinyRSA::getDecrypt(unsigned long Ciphered)
{
    return (unsigned char)ModulusPower(Ciphered, FD, FN);
}
//---------------------------------------------------------------------------
