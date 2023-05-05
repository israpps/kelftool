/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>

#include "keystore.h"
#include "kelf.h"

// TODO: implement load/save kelf header configuration for byte-perfect encryption, decryption

std::string getKeyStorePath()
{
#if defined(__linux__) || defined(__APPLE__)
    return std::string(getenv("HOME")) + "/PS2KEYS.dat";
#else
    return std::string(getenv("USERPROFILE")) + "\\PS2KEYS.dat";
#endif
}

int decrypt(int argc, char **argv)
{
    if (argc < 3) {
        printf("%s decrypt <input> <output>\n", argv[0]);
        return -1;
    }

    KeyStore ks;
    int ret = ks.Load(getKeyStorePath());
    if (ret != 0) {
        // try to load keys from working directory
        ret = ks.Load("./PS2KEYS.dat");
        if (ret != 0) {
            printf("Failed to load keystore: %d - %s\n", ret, KeyStore::getErrorString(ret).c_str());
            return ret;
        }
    }

    Kelf kelf(ks);
    ret = kelf.LoadKelf(argv[1]);
    if (ret != 0) {
        printf("Failed to LoadKelf %d!\n", ret);
        return ret;
    }
    ret = kelf.SaveContent(argv[2]);
    if (ret != 0) {
        printf("Failed to SaveContent!\n");
        return ret;
    }

    return 0;
}

int encrypt(int argc, char **argv)
{

    int headerid = HEADERID::INVALID;
    int Kbitid   = HEADERID::INVALID;
    int systemtype = SYSTEM_TYPE_PS2;
    if (argc < 4) {
        printf("%s encrypt --header=<headerid> --kbit=<kbit> [extra args] <input> <output>\n", argv[0]);
        printf("<headerid>: fmcb, fhdb, mbr, dnasload\n");
        printf("<kbit>: fmcb, fhdb, mbr\n");
        printf("extra args:\n");
        printf("\t--system=[PS2|PSX]\n");
        return -1;
    }

    for (int x = 1; x < argc; x++)
    {
        if (!strncmp("--header=", argv[x], 10) && headerid == HEADERID::INVALID)
        {
            if (strcmp("fmcb", argv[x]+10) == 0)
                headerid = HEADERID::FMCB;

            if (strcmp("fhdb", argv[x]+10) == 0)
                headerid = HEADERID::FHDB;

            if (strcmp("mbr", argv[x]+10) == 0)
                headerid = HEADERID::MBR;

            if (strcmp("dnasload", argv[x]+10) == 0)
                headerid = HEADERID::DNASLOAD;

            if (headerid == HEADERID::INVALID)
            {
                printf("Invalid header ID (%s)\n", argv[x]+10);
                return -1;
            } else printf("using %s header...\n", argv[x]+10);
        }
        if (!strncmp("--kbit=", argv[x], 8) && Kbitid == HEADERID::INVALID)
        {
            if (strcmp("fmcb", argv[x]+8) == 0)
                Kbitid = HEADERID::FMCB;

            if (strcmp("fhdb", argv[x]+8) == 0)
                Kbitid = HEADERID::FHDB;

            if (strcmp("mbr", argv[x]+8) == 0)
                Kbitid = HEADERID::MBR;

            if (Kbitid == HEADERID::INVALID)
            {
                printf("Invalid kbit ID (%s)\n", argv[x]+8);
                return -1;
            } else printf("using %s kbit...\n", argv[x+8]);
        }
        if (!strncmp("--system=", argv[x], 10))
        {
            if (strcmp("PS2", argv[x]+10) == 0)
                systemtype = SYSTEM_TYPE_PS2;

            if (strcmp("PSX", argv[x]+10) == 0)
            {
                systemtype = SYSTEM_TYPE_PSX;
                printf("flagging as PSX-DESR KELF...\n");
            }
        }
    }

    KeyStore ks;
    int ret = ks.Load(getKeyStorePath());
    if (ret != 0) {
        // try to load keys from working directory
        ret = ks.Load("./PS2KEYS.dat");
        if (ret != 0) {
            printf("Failed to load keystore: %d - %s\n", ret, KeyStore::getErrorString(ret).c_str());
            return ret;
        }
    }

    Kelf kelf(ks);
    ret = kelf.LoadContent(argv[argc-2], Kbitid);
    if (ret != 0) {
        printf("Failed to LoadContent!\n");
        return ret;
    }

    ret = kelf.SaveKelf(argv[argc-1], headerid, systemtype);
    if (ret != 0) {
        printf("Failed to SaveKelf!\n");
        return ret;
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s <submodule> <args>\n", argv[0]);
        printf("Available submodules:\n");
        printf("\tdecrypt --> decrypt and check signature of kelf files\n");
        printf("\tencrypt --header=<headerid> --kbit=<kbitid> [optional args] 'input KELF' 'Output KELF' --> encrypt and sign kelf files\n");
        printf("\t\t headerid:\n");
        printf("\t\t\tfmcb     - for retail PS2 memory cards\n");
        printf("\t\t\tdnasload - for retail PS2 memory cards (decrypts on both PS2 and PSX. some sort of 'universal KELF')\n");
        printf("\t\t\tfhdb     - for retail PS2 HDD (HDD OSD / BB Navigator)\n");
        printf("\t\t\tmbr      - for retail PS2 HDD (mbr injection).\n");
        printf("\t\t kbit:\n");
        printf("\t\t\tfmcb     - for retail PS2 memory cards\n");
        printf("\t\t\tfhdb     - for retail PS2 HDD (HDD OSD / BB Navigator)\n");
        printf("\t\t\tmbr      - for retail PS2 HDD (mbr injection).\n");
        printf("\t\t       Note: for mbr elf should load from 0x100000 and should be without headers:\n");
        printf("\t\t       readelf -h <input_elf> should show 0x100000 or 0x100008\n");
        printf("\t\t       $(EE_OBJCOPY) -O binary -v <input_elf> <headerless_elf>\n");
        printf("\t\tExtra args:\n");
        printf("\t\t\t--system=[PS2|PSX]\n");
        return -1;
    }

    char *cmd = argv[1];
    argv[1]   = argv[0];
    argc--;
    argv++;

    if (strcmp("decrypt", cmd) == 0)
        return decrypt(argc, argv);
    else if (strcmp("encrypt", cmd) == 0)
        return encrypt(argc, argv);

    printf("Unknown submodule!\n");
    return -1;
}
