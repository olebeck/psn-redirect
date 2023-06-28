const char patch_0x81002596_0x810182f4[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0x7a, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xa2, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x5b, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0x94, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x66, 0xff, 0x09, 0xe0};

const char patch_0x81002596_0x81018354[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0xaa, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xd2, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x5b, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xc4, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x66, 0xff, 0x09, 0xe0};

const char patch_0x81002596_0x81018370[] = {0xdd, 0xf8, 0xbc, 0x40, 0x20, 0x46, 0xff, 0x21, 0x15, 0xf0, 0xb8, 0xef, 0x03, 0x46, 0x40, 0xf2, 0x00, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xe0, 0xee, 0x00, 0x28, 0x1b, 0xdd, 0x01, 0x46, 0xdb, 0xf8, 0xb0, 0x00, 0x09, 0xf0, 0x69, 0xff, 0xcd, 0xf8, 0xbc, 0x00, 0x21, 0x46, 0x41, 0xf2, 0x34, 0x22, 0x15, 0xf0, 0xd2, 0xee, 0xdb, 0xf8, 0xb4, 0x00, 0x21, 0x46, 0x09, 0xf0, 0x74, 0xff, 0x09, 0xe0};


int get_servername_patch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
	switch(module_nid) {
	case 0x751039e1: // 361-DEX
	case 0xb015b405: // 360-CEX
	case 0x356e041b: // 363-DEX
	case 0xe222489b: // 363-QAF, 363-TOOL
	case 0x548b4754: // 361-CEX
	case 0x72aab836: // 360-DEX
	case 0x545b24b7: // 363-CEX
	case 0xf7c71fbb: // 361-TOOL
	case 0x776f287d: // 360-TOOL
	case 0xbea1205f: // 360-QAF
		*patch = patch_0x81002596_0x810182f4;
		*patch_size = sizeof(patch_0x81002596_0x810182f4);
		*offset = 0x2596;
		break;
	case 0x6cc68689: // 367-DEX
	case 0xa4ee4fd0: // 368-TOOL
	case 0x65d8aa31: // 367-CEX
	case 0xd90c9b72: // 368-CEX
	case 0xd172bcd3: // 365-TOOL
	case 0x9ee29c74: // 365-DEX
	case 0x40403cf5: // 368-DEX
	case 0x7b2c16b7: // 367-TOOL
	case 0xf8ac499b: // 365-CEX
		*patch = patch_0x81002596_0x81018354;
		*patch_size = sizeof(patch_0x81002596_0x81018354);
		*offset = 0x2596;
		break;
	case 0x0fbd68a0: // 373-TOOL
	case 0xe14bbda1: // 373-CEX
	case 0x8a536365: // 371-CEX
	case 0x963fbaea: // 372-DEX
	case 0x12c12f6c: // 371-TOOL
	case 0x861b880e: // 372-QAF
	case 0xf82fc630: // 370-CEX
	case 0x27de0e91: // 372-CEX
	case 0x02733194: // itls
	case 0xda3a5e57: // 369-CEX
	case 0x4deb60db: // 374-CEX
		*patch = patch_0x81002596_0x81018370;
		*patch_size = sizeof(patch_0x81002596_0x81018370);
		*offset = 0x2596;
		break;
	default:
		return -1;
	}
	return 0;
}