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
    int SysType = SYSTEM_TYPE_PS2;
    int headerid = HEADERID::INVALID;
    int kbit_and_kc = HEADERID::INVALID;
    uint16_t kelf_flags = HDR_PFLAG_KELF;

    if (argc < 4) {
        printf("%s encrypt <input> <output> [flags]\n", argv[0]);
        printf("<headerid>: fmcb, fhdb, mbr, dnasload\n");
        return -1;
    }
    for (int x=3; x<argc; x++) {
        if (!strncmp(argv[x], "--header=", 9)) {
            if (strcmp("fmcb", &argv[x][9]) == 0)
                headerid = HEADERID::FMCB;

            if (strcmp("fhdb", &argv[x][9]) == 0)
                headerid = HEADERID::FHDB;

            if (strcmp("mbr", &argv[x][9]) == 0)
                headerid = HEADERID::MBR;

            if (strcmp("dnasload", &argv[x][9]) == 0)
                headerid = HEADERID::DNASLOAD;

            if (headerid == HEADERID::INVALID) {
                printf("Invalid header: %s\nAvailable Headers:", &argv[x][9]);
                printf("\tfmcb     - for retail PS2 memory cards\n");
                printf("\tdnasload - decrypts on both PS2 and PSX. some sort of 'universal KELF'\n");
                printf("\tfhdb     - for retail PS2 HDD (HDD OSD / BB Navigator)\n");
                printf("\tmbr      - for retail PS2 HDD (mbr injection).\n");
                printf("\t       Note: for mbr elf should load from 0x100000 and should be without headers:\n");
                return -1;
            }
        } else if (!strncmp(argv[x], "--kbitkc=", 9)) {
            if (strcmp("fmcb", &argv[x][9]) == 0)
                kbit_and_kc = HEADERID::FMCB;

            if (strcmp("fhdb", &argv[x][9]) == 0)
                kbit_and_kc = HEADERID::FHDB;

            if (strcmp("mbr", &argv[x][9]) == 0)
                kbit_and_kc = HEADERID::MBR;

            if (kbit_and_kc == HEADERID::INVALID) {
                printf("Invalid Kbit & Kc: %s\n", &argv[x][9]);
                return -1;
            }
        } else if (!strncmp(argv[x], "--systemtype=", 13)) {
            if (strcmp("PS2", &argv[x][13]) == 0)
                SysType = SYSTEM_TYPE_PS2;

            if (strcmp("PSX", &argv[x][13]) == 0)
                SysType = SYSTEM_TYPE_PSX;
        } else if (!strncmp(argv[x], "--kflags=", 9)) {
            if (strcmp("kelf", &argv[x][13]) == 0)
                kelf_flags = HDR_PFLAG_KELF;

            if (strcmp("kirx", &argv[x][13]) == 0)
                kelf_flags = HDR_PFLAG_KIRX;
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

    if (SysType == SYSTEM_TYPE_PSX)
        printf("-- PSX System Type selected. KELF Will only work on a PSX-DESR\n");

    Kelf kelf(ks);
    ret = kelf.LoadContent(argv[1], headerid);
    if (ret != 0) {
        printf("Failed to LoadContent!\n");
        return ret;
    }

    ret = kelf.SaveKelf(argv[2], headerid, SysType, kelf_flags);
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
        printf("\tdecrypt - decrypt and check signature of kelf files\n");
        printf("\tencrypt <headerid> - encrypt and sign kelf files <headerid>: fmcb, dnasload, fhdb, mbr\n");
        printf("\t\tfmcb     - for retail PS2 memory cards\n");
        printf("\t\tdnasload - for retail PS2 memory cards (decrypts on both PS2 and PSX. some sort of 'universal KELF')\n");
        printf("\t\tfhdb     - for retail PS2 HDD (HDD OSD / BB Navigator)\n");
        printf("\t\tmbr      - for retail PS2 HDD (mbr injection).\n");
        printf("\t\t       Note: for mbr elf should load from 0x100000 and should be without headers:\n");
        printf("\t\t       readelf -h <input_elf> should show 0x100000 or 0x100008\n");
        printf("\t\t       $(EE_OBJCOPY) -O binary -v <input_elf> <headerless_elf>\n");
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
