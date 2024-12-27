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
#ifndef TinyRSAUH
#define TinyRSAUH
//---------------------------------------------------------------------------
#include <classes.hpp>
//---------------------------------------------------------------------------

#define TINYRSA_PRIVATE_EXPOSURE

class TinyRSA
{
private:
    unsigned __int64 FN;
    unsigned short   FE;
    unsigned __int64 FD;
    unsigned long    FP;
    unsigned long    FQ;
    unsigned __int64 FLambdaN;

protected:
    static unsigned __int64 GreatestCommonDivisor       (unsigned __int64 A, unsigned __int64 B);
    static unsigned __int64 LowestCommonMultiple        (unsigned __int64 A, unsigned __int64 B);
    static unsigned __int64 ModularMultiplicativeInverse(unsigned __int64 A, unsigned __int64 B);
    static bool             IsPrime                     (unsigned long Prime);
    static unsigned long    GeneratePrime();

           unsigned long    getCrypt  (unsigned char Plain);
           unsigned char    getDecrypt(unsigned long Ciphered);

public:
    TinyRSA();

    // ModulusPower is public because it's needed for encryption and decryption
    static unsigned __int64 ModulusPower(unsigned __int64 Base, unsigned __int64 Power, unsigned __int64 Mod);

    static void GeneratePrimes( unsigned short    E,
                                unsigned long    &P,
                                unsigned long    &Q,
                                unsigned __int64 &N,
                                unsigned __int64 &LambdaN);

    static void GenerateKeyPair(unsigned __int64 &N,        // Public  \---> N + E = Public Key
                                unsigned short   &E,        // Public  /
                                unsigned __int64 &D,        // Private ----> N + D = Private Key
                                unsigned long    &P,        // KEEP private (after D it's no longer necessary)
                                unsigned long    &Q,        // KEEP private (after D it's no longer necessary)
                                unsigned __int64 &LambdaN); // KEEP private (after D it's no longer necessary)

           void GenerateKeyPair();

    __property unsigned __int64 N = { read = FN, write = FN }; // Writable for Crypt
    __property unsigned short   E = { read = FE, write = FE }; // Writable for Crypt
#ifdef TINYRSA_PRIVATE_EXPOSURE
    __property unsigned __int64 D = { read = FD };
    __property unsigned long    P = { read = FP };
    __property unsigned long    Q = { read = FQ };
    __property unsigned __int64 LambdaN = { read = FLambdaN };
#endif
    __property unsigned long    Crypt  [unsigned char Plain]    = { read = getCrypt   };
    __property unsigned char    Decrypt[unsigned long Ciphered] = { read = getDecrypt };
};
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
#endif
//---------------------------------------------------------------------------
