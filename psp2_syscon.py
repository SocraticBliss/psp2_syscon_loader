#!/usr/bin/env python
'''

PS Vita Syscon Loader by SocraticBliss and CelesteBlue (R)

Couldn't have done it without you Pablo!

Dedicated to zecoxao <3

psp2_syscon.py: IDA loader for reading Sony PlayStation(R) Vita Syscon Firmware files

'''

from idaapi import *
from idc import *

import idaapi as ida
import idc

# Load Processor Details...
def processor(processor):
    
    # Processor
    idc.set_processor_type(processor, SETPROC_LOADER)
    
    # Assembler
    idc.set_target_assembler(0x0)
    
    # Compiler
    idc.set_inf_attr(INF_COMPILER, COMP_GNU)
    
    # Loader Flags
    idc.set_inf_attr(INF_LFLAGS, LFLG_PC_FLAT | LFLG_COMPRESS)
    
    # Assume GCC3 names
    idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3)
    
    # Analysis Flags
    idc.set_inf_attr(INF_AF, 0xBFFFBFFF)

# Pablo's Function Search...
def function_search(mode, search, address = 0):

    while address < BADADDR:
        address = ida.find_binary(address, BADADDR, search, 0x10, SEARCH_DOWN)
        if address < BADADDR:
            address += mode
            ida.do_unknown(address, 0)
            ida.add_func(address, BADADDR)
            address += 1

# Load Segment Details...
def segment(f, start, end, name, type = 'DATA', perm = SEGPERM_MAXVAL):

    f.file2base(start, start, end, FILEREG_PATCHABLE)
    flags = 0x0 if name in ['PA1', 'BFA', 'MIRROR'] else ADDSEG_NOAA
    ida.add_segm(0x0, start, end, name, type, flags)
    
    # Processor Specific Segment Details
    idc.set_segm_addressing(start, 0x1)
    idc.set_segm_alignment(start, saAbs)
    idc.set_segm_combination(start, scPriv)
    idc.set_segm_attr(start, SEGATTR_PERM, perm)


# PROGRAM START

# Open File Dialog...
def accept_file(f, n):
    
    try:
        if not isinstance(n, (int, long)) or n == 0:
            f.seek(0xC0)
            return 'PS Vita - Syscon' if f.read(4) == '\x7F\xFF\xAA\x04' else 0
    
    except:
        pass

# Load Input Binary...
def load_file(f, neflags, format):
    
    print('# PS Vita Syscon Loader')
    
    # PS Vita Syscon Processor
    processor('rl78')
    
    # 0x0 - 0x80
    print('# Creating Vector Table Area 0')
    segment(f, 0x0, 0x80, 'VTA0', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # 0x80 - 0xC0
    print('# Creating CALLT Table Area 0')
    segment(f, 0x80, 0xC0, 'CALLTTA0')
    
    for callt in xrange(0x20):
        address  = 0x80 + (callt * 2)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
    
    # 0xC0 - 0xC4
    print('# Creating Option Byte Area 0')
    segment(f, 0xC0, 0xC4, 'OBA0')
    
    ida.create_data(0xC0, FF_BYTE, 0x4, BADNODE)
    
    # 0xC4 - 0xCE
    print('# Creating On-chip Debug Security 0')
    segment(f, 0xC4, 0xCE, 'ODS0')
    
    ida.create_data(0xC4, FF_BYTE, 0xA, BADNODE)
    
    # 0xCE - 0x1000
    print('# Creating Program Area 0')
    segment(f, 0xCE, 0x1000, 'PA0', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # 0x1000 - 0x1080
    print('# Creating Vector Table Area 1')
    segment(f, 0x1000, 0x1080, 'VTA1')
    
    # 0x1080 - 0x10C0
    print('# Creating CALLT Table Area 1')
    segment(f, 0x1080, 0x10C0, 'CALLTTA1')
    
    for callt in xrange(0x20):
        address  = 0x1080 + (callt * 2)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
    
    # 0x10C0 - 0x10C4
    print('# Creating Option Byte Area 1')
    segment(f, 0x10C0, 0x10C4, 'OBA1')
    
    ida.create_data(0x10C0, FF_BYTE, 0x4, BADNODE)
    
    # 0x10C4 - 0x10CE
    print('# Creating On-chip Debug Security 1')
    segment(f, 0x10C4, 0x10CE, 'ODS1')
    
    ida.create_data(0x10C4, FF_BYTE, 0xA, BADNODE)
       
    # 0x10CE - 0x60000
    print('# Creating Program Area 1')
    segment(f, 0x10CE, 0x60000, 'PA1', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    VTA = [
        'RST',
        'INTDBG',
        'INTWDTI',
        'INTLVI',
        'INTP0',
        'INTP1',
        'INTP2',
        'INTP3',
        'INTP4',
        'INTP5',
        'INTST2',
        'INTSR2',
        'INTSRE2',
        'INTDMA0',
        'INTDMA1',
        'INTST0',
        'INTSR0',
        'INTSRE0',
        'INTST1',
        'INTSR1',
        'INTSRE1',
        'INTIICA0',
        'INTTM00',
        'INTTM01',
        'INTTM02',
        'INTTM03',
        'INTAD',
        'INTRTC',
        'INTIT',
        'INTKR',
        'INTST3',
        'INTSR3',
        'INTTM13',
        'INTTM04',
        'INTTM05',
        'INTTM06',
        'INTTM07',
        'INTP6',
        'INTP7',
        'INTP8',
        'INTP9',
        'INTP10',
        'INTP11',
        'INTTM10',
        'INTTM11',
        'INTTM12',
        'INTSRE3',
        'INTMD',
        'INTIICA1',
        'INTFL',
        'INTDMA2',
        'INTDMA3',
        'INTTM14',
        'INTTM15',
        'INTTM16',
        'INTTM17',
        '', # 0x70
        '', # 0x72
        '', # 0x74
        '', # 0x76
        '', # 0x78
        '', # 0x7A
        '', # 0x7C
        'BRK_I',
    ]
    
    # Create Additional Functions from VTA0
    address = 0x0
    for vec in VTA:
        function = ida.get_word(address)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        
        if vec != '':
            ida.set_name(address, vec, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        if function:
            ida.create_insn(function)
            ida.add_func(function, BADADDR)
            ida.op_plain_offset(address, 0, 0)
    
        address += 2
    
    # Create Additional Functions from VTA1
    address = 0x1000
    for vec in VTA:
        function = ida.get_word(address)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        
        if vec != '':
            ida.set_name(address, vec, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        if function:
            ida.create_insn(function)
            ida.add_func(function, BADADDR)
            ida.op_plain_offset(address, 0, 0)
    
        address += 2
    
    '''
    # 0x60000 - 0xEF000
    print('# Creating Guarded')
    segment(f, 0x60000, 0xEF000, 'GUARD')
    
    # Compress the segment
    ida.create_data(0x60000, FF_BYTE, 0x8F000, BADNODE)
    '''
    
    # 0xEF000 - 0xF0000
    print('# Creating Bootloader Flash Area')
    segment(f, 0xEF000, 0xF0000, 'BFA', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # Bootloader/Flash Programming Areas
    for entry in xrange(0xEFFF0, 0xF0000, 0x4):   
        ida.create_insn(entry)
        ida.add_func(entry, BADADDR)
        if entry == 0xEFFF8:
            ida.set_name(entry, 'FalshFirm', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # 0xF0000 - 0xF0800
    print('# Creating Special Function Registers 2')
    segment(f, 0xF0000, 0xF0800, 'SFR2')
    
    SFR2 = [
        (0xF0001, 0x1, 'ADM2', 'A/D converter mode register 2'),
        (0xF0011, 0x1, 'ADUL', 'Conversion result comparison upper limit setting register'),
        (0xF0012, 0x1, 'ADLL', 'Conversion result comparison lower limit setting register'),
        (0xF0013, 0x1, 'ADTES', 'A/D test register'),
        (0xF0030, 0x1, 'PU0', 'Pull-up resistor option register 0'),
        (0xF0031, 0x1, 'PU1', 'Pull-up resistor option register 1'),
        (0xF0033, 0x1, 'PU3', 'Pull-up resistor option register 3'),
        (0xF0034, 0x1, 'PU4', 'Pull-up resistor option register 4'),
        (0xF0035, 0x1, 'PU5', 'Pull-up resistor option register 5'),
        (0xF0036, 0x1, 'PU6', 'Pull-up resistor option register 6'),
        (0xF0037, 0x1, 'PU7', 'Pull-up resistor option register 7'),
        (0xF0038, 0x1, 'PU8', 'Pull-up resistor option register 8'),
        (0xF0039, 0x1, 'PU9', 'Pull-up resistor option register 9'),
        (0xF003A, 0x1, 'PU10', 'Pull-up resistor option register 10'),
        (0xF003B, 0x1, 'PU11', 'Pull-up resistor option register 11'),
        (0xF003C, 0x1, 'PU12', 'Pull-up resistor option register 12'),
        (0xF003E, 0x1, 'PU14', 'Pull-up resistor option register 14'),
        (0xF0040, 0x1, 'PIM0', 'Port input mode register 0'),
        (0xF0041, 0x1, 'PIM1', 'Port input mode register 1'),
        (0xF0044, 0x1, 'PIM4', 'Port input mode register 4'),
        (0xF0045, 0x1, 'PIM5', 'Port input mode register 5'),
        (0xF0048, 0x1, 'PIM8', 'Port input mode register 8'),
        (0xF004E, 0x1, 'PIM14', 'Port input mode register 14'),
        (0xF0050, 0x1, 'POM0', 'Port output mode register 0'),
        (0xF0051, 0x1, 'POM1', 'Port output mode register 1'),
        (0xF0054, 0x1, 'POM4', 'Port output mode register 4'),
        (0xF0055, 0x1, 'POM5', 'Port output mode register 5'),
        (0xF0057, 0x1, 'POM7', 'Port output mode register 7'),
        (0xF0058, 0x1, 'POM8', 'Port output mode register 8'),
        (0xF0059, 0x1, 'POM9', 'Port output mode register 9'),
        (0xF005E, 0x1, 'POM14', 'Port output mode register 14'),
        (0xF0060, 0x1, 'PMC0', 'Port mode control register 0'),
        (0xF0063, 0x1, 'PMC3', 'Port mode control register 3'),
        (0xF006A, 0x1, 'PMC10', 'Port mode control register 10'),
        (0xF006B, 0x1, 'PMC11', 'Port mode control register 11'),
        (0xF006C, 0x1, 'PMC12', 'Port mode control register 12'),
        (0xF006E, 0x1, 'PMC14', 'Port mode control register 14'),
        (0xF0070, 0x1, 'NFEN0', 'Noise filter enable register 0'),
        (0xF0071, 0x1, 'NFEN1', 'Noise filter enable register 1'),
        (0xF0072, 0x1, 'NFEN2', 'Noise filter enable register 2'),
        (0xF0073, 0x1, 'ISC', 'Input switch control register'),
    ]
    
    for (address, size, name, comment) in SFR2:
        flags = ida.get_flags_by_size(size)
        ida.create_data(address, flags, size, BADNODE)
        ida.set_name(address, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.set_cmt(address, comment, False)
    
    # 0xF0800 - 0xF1000
    print('# Creating Bootloader RAM')
    segment(f, 0xF0800, 0xF1000, 'BRAM')
    
    # 0xF1000 - 0xF3000
    print('# Creating Data Flash Memory')
    segment(f, 0xF1000, 0xF3000, 'EEPROM')
    
    # 0xF3000 - 0xF9F00
    print('# Creating Mirror')
    segment(f, 0xF3000, 0xF9F00, 'MIRROR', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # 0xF9F00 - 0xFFEE0
    print('# Creating RAM')
    segment(f, 0xF9F00, 0xFFEE0, 'RAM')
    
    # 0xFFEE0 - 0xFFF00
    print('# Creating General-purpose Registers')
    segment(f, 0xFFEE0, 0xFFF00, 'GPR')
    
    GPR = [ 'X', 'A', 'C', 'B', 'E', 'D', 'L', 'H' ]
    address = 0xFFEE0
    
    for gpr in xrange(0x4):
        for entry in GPR:
            ida.create_data(address, FF_BYTE, 0x1, BADNODE)
            ida.set_name(address, 'RB%i%s' % (gpr, entry), SN_NOCHECK | SN_NOWARN | SN_FORCE)
            address += 1
    
    # 0xFFF00 - 0xFFFFF
    print('# Creating Special Function Registers')
    segment(f, 0xFFF00, 0xFFFFF, 'SFR')
    
    SFR = [
        (0xFFF00, 0x1, 'P0', 'Port register 0'),
        (0xFFF01, 0x1, 'P1', 'Port register 1'),
        (0xFFF02, 0x1, 'P2', 'Port register 2'),
        (0xFFF03, 0x1, 'P3', 'Port register 3'),
        (0xFFF04, 0x1, 'P4', 'Port register 4'),
        (0xFFF05, 0x1, 'P5', 'Port register 5'),
        (0xFFF06, 0x1, 'P6', 'Port register 6'),
        (0xFFF07, 0x1, 'P7', 'Port register 7'),
        (0xFFF08, 0x1, 'P8', 'Port register 8'),
        (0xFFF09, 0x1, 'P9', 'Port register 9'),
        (0xFFF0A, 0x1, 'P10', 'Port register 10'),
        (0xFFF0B, 0x1, 'P11', 'Port register 11'),
        (0xFFF0C, 0x1, 'P12', 'Port register 12'),
        (0xFFF0D, 0x1, 'P13', 'Port register 13'),
        (0xFFF0E, 0x1, 'P14', 'Port register 14'),
        (0xFFF0F, 0x1, 'P15', 'Port register 15'),
        (0xFFF10, 0x2, 'SDR00', 'Serial data register 00'),
        (0xFFF12, 0x2, 'SDR01', 'Serial data register 01'),
        (0xFFF14, 0x2, 'SDR12', 'Serial data register 12'),
        (0xFFF16, 0x2, 'SDR13', 'Serial data register 13'),
        (0xFFF18, 0x2, 'TDR00', 'Timer data register 00'),
        (0xFFF1A, 0x2, 'TDR01', 'Timer data register 01'),        
        (0xFFF1E, 0x2, 'ADCR', '10-bit A/D conversion result register'),
        (0xFFF20, 0x1, 'PM0', 'Port mode register 0'),
        (0xFFF21, 0x1, 'PM1', 'Port mode register 1'),
        (0xFFF22, 0x1, 'PM2', 'Port mode register 2'),
        (0xFFF23, 0x1, 'PM3', 'Port mode register 3'),
        (0xFFF24, 0x1, 'PM4', 'Port mode register 4'),
        (0xFFF25, 0x1, 'PM5', 'Port mode register 5'),
        (0xFFF26, 0x1, 'PM6', 'Port mode register 6'),
        (0xFFF27, 0x1, 'PM7', 'Port mode register 7'),
        (0xFFF28, 0x1, 'PM8', 'Port mode register 8'),
        (0xFFF29, 0x1, 'PM9', 'Port mode register 9'),
        (0xFFF2A, 0x1, 'PM10', 'Port mode register 10'),
        (0xFFF2B, 0x1, 'PM11', 'Port mode register 11'),
        (0xFFF2C, 0x1, 'PM12', 'Port mode register 12'),
        (0xFFF2E, 0x1, 'PM14', 'Port mode register 14'),
        (0xFFF2F, 0x1, 'PM15', 'Port mode register 15'),
        (0xFFF30, 0x1, 'ADM0', 'A/D converter mode register 0'),
        (0xFFF31, 0x1, 'ADS', 'Analog input channel specification register'),
        (0xFFF32, 0x1, 'ADM1', 'A/D converter mode register 1'),
        (0xFFF37, 0x1, 'KRM', 'Key return mode register'),
        (0xFFF38, 0x1, 'EGP0', 'External interrupt rising edge enable register 0'),
        (0xFFF39, 0x1, 'EGN0', 'External interrupt falling edge enable register 0'),
        (0xFFF3A, 0x1, 'EGP1', 'External interrupt rising edge enable register 1'),
        (0xFFF3B, 0x1, 'EGN1', 'External interrupt falling edge enable register 1'),
        (0xFFF44, 0x2, 'SDR02', 'Serial data register 02'),
        (0xFFF46, 0x2, 'SDR03', 'Serial data register 03'),
        (0xFFF48, 0x2, 'SDR10', 'Serial data register 10'),
        (0xFFF4A, 0x2, 'SDR11', 'Serial data register 11'),
        (0xFFF50, 0x1, 'IICA0', 'IICA shift register 0'),
        (0xFFF51, 0x1, 'IICS0', 'IICA status register 0'),
        (0xFFF52, 0x1, 'IICF0', 'IICA flag register 0'),
        (0xFFF54, 0x1, 'IICA1', 'IICA shift register 1'),
        (0xFFF55, 0x1, 'IICS1', 'IICA status register 1'),
        (0xFFF56, 0x1, 'IICF1', 'IICA flag register 1'),
        (0xFFF64, 0x2, 'TDR02', 'Timer data register 02'),
        (0xFFF66, 0x2, 'TDR03', 'Timer data register 03'),
        (0xFFF68, 0x2, 'TDR04', 'Timer data register 04'),
        (0xFFF6A, 0x2, 'TDR05', 'Timer data register 05'),
        (0xFFF6C, 0x2, 'TDR06', 'Timer data register 06'),
        (0xFFF6E, 0x2, 'TDR07', 'Timer data register 07'),
        (0xFFF70, 0x2, 'TDR10', 'Timer data register 10'),
        (0xFFF72, 0x2, 'TDR11', 'Timer data register 11'),
        (0xFFF74, 0x2, 'TDR12', 'Timer data register 12'),
        (0xFFF76, 0x2, 'TDR13', 'Timer data register 13'),
        (0xFFF78, 0x2, 'TDR14', 'Timer data register 14'),
        (0xFFF7A, 0x2, 'TDR15', 'Timer data register 15'),
        (0xFFF7C, 0x2, 'TDR16', 'Timer data register 16'),
        (0xFFF7E, 0x2, 'TDR17', 'Timer data register 17'),
        (0xFFF90, 0x2, 'ITMC', 'Interval timer control register'),
        (0xFFF92, 0x1, 'SEC', 'Second count register'),
        (0xFFF93, 0x1, 'MIN', 'Minute count register'),
        (0xFFF94, 0x1, 'HOUR', 'Hour count register'),
        (0xFFF95, 0x1, 'WEEK', 'Week count register'),
        (0xFFF96, 0x1, 'DAY', 'Day count register'),
        (0xFFF97, 0x1, 'MONTH', 'Month count register'),
        (0xFFF98, 0x1, 'YEAR', 'Year count register'),
        (0xFFF99, 0x1, 'SUBCUD', 'Watch error correction register'),
        (0xFFF9A, 0x1, 'ALARMWM', 'Alarm minute register'),
        (0xFFF9B, 0x1, 'ALARMWH', 'Alarm hour register'),
        (0xFFF9C, 0x1, 'ALARMWW', 'Alarm week register'),
        (0xFFF9D, 0x1, 'RTCC0', 'Real-time clock control register 0'),
        (0xFFF9E, 0x1, 'RTCC1', 'Real-time clock control register 1'),
        (0xFFFA0, 0x1, 'CMC', 'Clock operation mode control register'),
        (0xFFFA1, 0x1, 'CSC', 'Clock operation status control register'),
        (0xFFFA2, 0x1, 'OSTC', 'Oscillation stabilization time counter status register'),
        (0xFFFA3, 0x1, 'OSTS', 'Oscillation stabilization time select register'),
        (0xFFFA4, 0x1, 'CKC', 'System clock control register'),
        (0xFFFA5, 0x1, 'CKS0', 'Clock output select register 0'),
        (0xFFFA6, 0x1, 'CKS1', 'Clock output select register 1'),
        (0xFFFA8, 0x1, 'RESF', 'Reset control flag register'),
        (0xFFFA9, 0x1, 'LVIM', 'Voltage detection register'),
        (0xFFFAA, 0x1, 'LVIS', 'Voltage detection level register'),
        (0xFFFAB, 0x1, 'WDTE', 'Watchdog timer enable register'),
        (0xFFFAC, 0x1, 'CRCIN', 'CRC input register'),
        (0xFFFB0, 0x1, 'DSA0', 'DMA SFR address register 0'),
        (0xFFFB1, 0x1, 'DSA1', 'DMA SFR address register 1'),
        (0xFFFB2, 0x2, 'DRA0', 'DMA RAM address register 0'),
        (0xFFFB4, 0x2, 'DRA1', 'DMA RAM address register 1'),
        (0xFFFB6, 0x2, 'DBC0', 'DMA byte count register 0'),
        (0xFFFB8, 0x2, 'DBC1', 'DMA byte count register 1'),
        (0xFFFBA, 0x1, 'DMC0', 'DMA mode control register 0'),
        (0xFFFBB, 0x1, 'DMC1', 'DMA mode control register 1'),
        (0xFFFBC, 0x1, 'DRC0', 'DMA operation control register 0'),
        (0xFFFBD, 0x1, 'DRC1', 'DMA operation control register 1'),
        (0xFFFD0, 0x2, 'IF2', 'Interrupt request flag register 2'),
        (0xFFFD2, 0x2, 'IF3', 'Interrupt request flag register 3'),
        (0xFFFD4, 0x2, 'MK2', 'Interrupt mask flag register 2'),
        (0xFFFD6, 0x2, 'MK3', 'Interrupt mask flag register 3'),
        (0xFFFD8, 0x2, 'PR02', 'Priority specification flag register 02'),
        (0xFFFDA, 0x2, 'PR03', 'Priority specification flag register 03'),
        (0xFFFDC, 0x2, 'PR12', 'Priority specification flag register 12'),
        (0xFFFDE, 0x2, 'PR13', 'Priority specification flag register 13'),
        (0xFFFE0, 0x2, 'IF0', 'Interrupt request flag register 0'),
        (0xFFFE2, 0x2, 'IF1', 'Interrupt request flag register 1'),
        (0xFFFE4, 0x2, 'MK0', 'Interrupt mask flag register 0'),
        (0xFFFE6, 0x2, 'MK1', 'Interrupt mask flag register 1'),
        (0xFFFE8, 0x2, 'PR00', 'Priority specification flag register 00'),
        (0xFFFEA, 0x2, 'PR01', 'Priority specification flag register 01'),
        (0xFFFEC, 0x2, 'PR10', 'Priority specification flag register 10'),
        (0xFFFEE, 0x2, 'PR11', 'Priority specification flag register 11'),
        (0xFFFF0, 0x2, 'MDAL', 'Multiplication/division data register A (L)'),
        (0xFFFF2, 0x2, 'MDAH', 'Multiplication/division data register A (H)'),
        (0xFFFF4, 0x2, 'MDBH', 'Multiplication/division data register B (H)'),
        (0xFFFF6, 0x2, 'MDBL', 'Multiplication/division data register B (L)'),
        (0xFFFFE, 0x1, 'PMC', 'Processor mode control register'),
    ]
    
    for (address, size, name, comment) in SFR:
        flags = ida.get_flags_by_size(size)
        ida.create_data(address, flags, size, BADNODE)
        ida.set_name(address, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.set_cmt(address, comment, False)
    
    # --------------------------------------------------------------------------------------------------------
    # Common
    
    pa1    = ida.get_segm_by_name('PA1')
    bfa    = ida.get_segm_by_name('BFA')
    mirror = ida.get_segm_by_name('MIRROR')
    
    # --------------------------------------------------------------------------------------------------------
    # sc_cmd_entry - Find Command Table
    
    COMMANDS = {
        0x05   : 'Get_Hardware_Info',
        0xD2   : 'SNVS_Read_Write',
        0x1082 : 'NVS_Read',
    }
    
    entry = idc.add_struc(BADADDR, 'sc_cmd_entry', False)
    idc.add_struc_member(entry, 'cmd',  0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'flag', 0x2, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'func', 0x4, 0x20500400, 0x0, 0x4, BADADDR, 0x0, 0x2)
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 sc_cmd_entry    
    # USS1001 - 0x26BE
    # USS1002 - 0x3096
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '00 00 00 00 ?? ?? 03 00 01 00', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    while True:
        command  = ida.get_word(address)
        flags    = ida.get_word(address + 0x2)
        function = ida.get_dword(address + 0x4)
        
        command = COMMANDS.get(command, 'cmd_0x%X_flags_0x%X' % (command, flags))
        ida.set_name(function, command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x2085:
            break
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror sc_cmd_entry
    # USS1001 - None
    # USS1002 - 0xF3096
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '00 00 00 00 ?? ?? 03 00 01 00', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR:
        while True:
            ida.create_struct(address, 0x8, entry)
            if ida.get_word(address) == 0x2085:
                break
            address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # sc_ext_cmd_entry - Find External Command Table
    
    entry = idc.add_struc(BADADDR, 'sc_ext_cmd_entry', False)
    idc.add_struc_member(entry, 'id', 0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'func',	0x2, 0x20500400, 0x0, 0x4, BADADDR, 0x0, 0x2)
    idc.add_struc_member(entry, 'flags', 0x6, 0x10000400, BADADDR, 0x2)
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 sc_ext_cmd_entry
    # USS1001 - 0x2D02
    # USS1002 - 0x3922
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '00 01 ?? ?? 00 00 00 00 01 01', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    while True:
        command  = ida.get_word(address)
        function = ida.get_dword(address + 0x2)
        flags    = ida.get_word(address + 0x6)
        
        ida.set_name(function, 'ext_cmd_0x%X_flags_0x%X' % (command, flags), SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x301:
            break
        address += 0x8
    
    # -------------------------------------------------------------------------------------------------------
    # Mirror sc_ext_cmd_entry
    # USS1001 - None
    # USS1002 - 0xF3922
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '00 01 ?? ?? 00 00 00 00 01 01', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR: 
        while True:
            ida.create_struct(address, 0x8, entry)
            if ida.get_word(address) == 0x301:
                break
            address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # sc_ext_cmd_entry - Find External Command Table 2
    # USS1001 - 0xF99C
    # USS1002 - 0x10424
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '97 D5 00 01 ?? ?? 01 00 00 00 01 01', 0x10, SEARCH_DOWN) + 0x2
    #print('address: 0x%X' % address)
    
    while True:
        command  = ida.get_word(address)
        function = ida.get_dword(address + 0x2)
        flags    = ida.get_word(address + 0x6)
        
        if flags == 0x161:
            break
        ida.set_name(function, 'ext_cmd_0x%X_flags_0x%X' % (command, flags), SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # sc_ext_cmd_entry - Find External Command Table 3
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '00 00 ?? ?? 01 00 00 00 01 00', 0x10, SEARCH_DOWN)
    # USS1001 - 0xF49E
    # USS1001 - 0xF60E
    # USS1002 - 0x1000E
    # USS1002 - 0x1019E
    
    if address != BADADDR:
        while True:
            command  = ida.get_word(address)
            function = ida.get_dword(address + 0x2)
            flags    = ida.get_word(address + 0x6)
            
            if command == 0x5224 or flags == 0x181:
                break
            ida.set_name(function, 'ext_cmd_0x%X_flags_0x%X' % (command, flags), SN_NOCHECK | SN_NOWARN | SN_FORCE)
            ida.create_struct(address, 0x8, entry)
            address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # renesas_cmd_entry - Find Renesas Command Table
    
    COMMANDS = {
        0x00 : 'Reset',
        0x13 : 'Verify',
        0x14 : 'OCD_Related',
        0x20 : 'Chip_Erase',
        0x22 : 'Block_Erase',
        0x32 : 'Block_Blank_Check',
        0x40 : 'Programming',
        0x9A : 'Baud_Rate_Set',
        0xA0 : 'Security_Set',
        0xA1 : 'Security_Get',
        0xA2 : 'Security_Release',
        0xB0 : 'Checksum',
        0xC0 : 'Silicon_Signature',
        0xC5 : 'Version_Get',
    }
    
    entry = idc.add_struc(BADADDR, 'renesas_cmd_entry', False)
    idc.add_struc_member(entry, 'version',	0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'ext_function_address', 0x2, 0x10000400, BADADDR, 0x32)
    idc.add_struc_member(entry, 'ext_function_code', 0x34,	0x400, BADADDR, 0xC)
    idc.add_struc_member(entry, 'unknown',	0x40, 0x400, BADADDR, 0x20)
    idc.add_struc_member(entry, 'int_function_address', 0x60, 0x10000400, BADADDR, 0x10)
    idc.add_struc_member(entry, 'int_function_code', 0x70,	0x400, BADADDR, 0x8)
    idc.add_struc_member(entry, 'unknown2', 0x78, 0x400, BADADDR, 0x1A)
    
    address = ida.find_binary(bfa.start_ea, bfa.end_ea, '03 03', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
    
    ida.create_struct(address - 0x2, 0x92, entry)
    
    # --------------------------------------------------------------------------------------------------------
    # External Functions
    
    ext_functions = []
    while ida.get_word(address) != 0x1300:
        ext_function = ida.get_word(address) + 0xE0000
        #print('ext_function: 0x%X' % ext_function)
        
        ida.create_insn(ext_function)
        if ida.print_insn_mnem(ext_function) != 'nop':
            ida.add_func(ext_function, BADADDR)
        
        '''
        print(ida.print_insn_mnem(ext_function + 0x3))
        if ida.print_insn_mnem(ext_function + 0x3) == 'br':
            ida.add_func(ext_function, ext_function + 0x5)
        else:
            ida.add_func(ext_function, BADADDR)
        '''
        
        ext_functions.append(ext_function)
        
        address += 2
    
    # --------------------------------------------------------------------------------------------------------
    # External Commands
    
    while ida.get_byte(address) != 0x3:
        command = ida.get_byte(address)
        #print('ext_function: 0x%X' % ext_functions[0])
        
        command = COMMANDS.get(command, 'renesas_ext_cmd_0x%X' % command)
        ida.set_name(ext_functions[0], command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        ext_functions.pop(0)
        
        address += 0x1
    
    address += 0x20
    #print('int_function_start: 0x%X' % address)
    
    # --------------------------------------------------------------------------------------------------------
    # Internal Functions
    
    int_functions = []
    while ida.get_word(address) != 0xCD0E:
        int_function = ida.get_word(address) + 0xE0000
        #print('int_function: 0x%X' % int_function)
        
        ida.create_insn(int_function)
        if ida.print_insn_mnem(int_function) != 'nop':
            ida.add_func(int_function, BADADDR)
        
        int_functions.append(int_function)
        
        address += 2
    
    # --------------------------------------------------------------------------------------------------------
    # Internal Commands
    
    while ida.get_byte(address) != 0x87:
        command = ida.get_byte(address)
        #print('int_function: 0x%X' % int_functions[0])
        
        command = COMMANDS.get(command, 'renesas_int_cmd_0x%X' % command)
        ida.set_name(int_functions[0], command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        int_functions.pop(0)
        
        address += 0x1
    
    # --------------------------------------------------------------------------------------------------------
    # Signature Data
    
    entry = idc.add_struc(BADADDR, 'signature_data', False)
    idc.add_struc_member(entry, 'device_code', 0x0,	0x400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'device_name', 0x3,	0x5000c400,	0,	0xA);
    idc.add_struc_member(entry, 'code_flash_mem_area_last_address',	0xD, 0x9400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'data_flash_mem_area_last_address', 0x10, 0x400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'firmware_version', 0x13, 0x400, BADADDR, 0x3);
    
    address = ida.find_binary(bfa.start_ea, bfa.end_ea, '10 00 06', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    ida.create_struct(address, 0x16, entry)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Command Keys    
    
    KEYS = [
        'SharedData_B',
        'SharedKey_B_A',
        'SharedKey_B_B',
        'SharedData_F_A',
        'SharedData_F_B',
        'SharedKey_F_A',
        'SharedKey_F_B',
        'SharedKey_F_C',
    ]    
    
    entry = idc.add_struc(BADADDR, 'key', False)
    idc.add_struc_member(entry, 'key', 0, 0x400, BADADDR, 0x10)    
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, 'CF 2E 93 E9 F9 4E 28 CC', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Command Keys 2
    
    address = ida.find_binary(address, pa1.end_ea, 'CF 2E 93 E9 F9 4E 28 CC', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR:
        ida.del_items(address, 0, size)
        
        for key in KEYS:
            ida.create_data(address, FF_BYTE, 0x10, BADNODE)
            ida.create_struct(address, 0x10, entry)
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            address += 0x10
        
    # --------------------------------------------------------------------------------------------------------
    # SP1 Unknown Command Keys
    
    KEYS = [
        'SharedData_0',
        'SharedKey_0_A',
        'SharedKey_0_B',
        'SharedData_1',
        'SharedKey_1_A',
        'SharedKey_1_B',
        'SharedData_E',
        'SharedKey_E_A',
        'SharedKey_E_B',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '80 99 6F BB C8 B4 EB A3', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    #print('address: 0x%X' % address)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Unknown Command Keys 2
    
    set2 = ida.find_binary(address, pa1.end_ea, '80 99 6F BB C8 B4 EB A3', 0x10, SEARCH_DOWN)
    print('address: 0x%X' % set2)
    
    if set2 != BADADDR:
        ida.del_items(set2, 0, size)
    
        for key in KEYS:
            ida.create_data(set2, FF_BYTE, 0x10, BADNODE)
            ida.create_struct(set2, 0x10, entry)
            ida.set_name(set2, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            set2 += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 g_debug_challenge_key
    
    ida.del_items(address, 0, 0x20)
    ida.create_data(address, FF_BYTE, 0x20, BADNODE)
    ida.set_name(address, 'g_debug_challenge_key', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    address += 0x20
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 g_debug_challenge_key 2
    
    set2 = ida.find_binary(address, pa1.end_ea, 'F4 77 16 E6 C5 64 9F D6', 0x10, SEARCH_DOWN)
    
    if set2 != BADADDR:
        ida.del_items(set2, 0, 0x20)
        ida.create_data(set2, FF_BYTE, 0x20, BADNODE)
        ida.set_name(set2, 'g_debug_challenge_key_0', SN_NOCHECK | SN_NOWARN | SN_FORCE)
        set2 += 0x20
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 jigkick_expansion
    
    KEYS = [
        'jigkick_expansion_0',
        'jigkick_expansion_1',
        'jigkick_expansion_2',
        'jigkick_expansion_3',
        'jigkick_expansion_4',
        'jigkick_expansion_5',
        'jigkick_expansion_6',
        'jigkick_expansion_7',
        'jigkick_expansion_8',
        'jigkick_expansion_9',
        'jigkick_expansion_A',
        'jigkick_expansion_B',
        'jigkick_expansion_C',
    ]
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 jigkick_expansion 2
    
    if set2 != BADADDR:
        ida.del_items(set2, 0, size)
        
        for key in KEYS:
            ida.create_data(set2, FF_BYTE, 0x10, BADNODE)
            ida.create_struct(set2, 0x10, entry)
            ida.set_name(set2, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            set2 += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Unknown Shared Keys
    
    KEYS = [
        'SharedKey_0',
        'SharedKey_1',
        'SharedKey_E',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '55 55 55 00', 0x10, SEARCH_DOWN) + 0x4
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0xE
    ida.del_items(address, 0, size)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    ida.del_items(address, 0, size)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Shared Keys
    
    KEYS = [
        'SharedKey_B',
        'SharedKey_F',
    ]
    
    extra = len(KEYS) * 0x16
    ida.del_items(address, 0, extra)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xE,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x12, FF_DWORD, 0x4, BADNODE)
        
        address += 0x16
    
    ida.del_items(address, 0, size)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 MISC Keys/Data
    
    KEYS = [
        'AES_KEY',
        'AES_IV',
        'XOR_KEY',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, 'DB D9 45 0A CC A8 54 48', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 SERVICE_0x900_DATA
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x10)
    ida.create_data(address, FF_BYTE, 0x10, BADNODE)
    ida.create_struct(address, 0x10, entry)
    ida.set_name(address, 'SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 SERVICE_0x900_DATA 2
    
    address = ida.find_binary(address, pa1.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x10)
    ida.create_data(address, FF_BYTE, 0x10, BADNODE)
    ida.create_struct(address, 0x10, entry)
    ida.set_name(address, 'SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Command Keys    
    
    KEYS = [
        '_SharedData_B',
        '_SharedKey_B_A',
        '_SharedKey_B_B',
        '_SharedData_F_A',
        '_SharedData_F_B',
        '_SharedKey_F_A',
        '_SharedKey_F_B',
        '_SharedKey_F_C',
    ]
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, 'CF 2E 93 E9 F9 4E 28 CC', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR:
        
        size = len(KEYS) * 0x10
        ida.del_items(address, 0, size)
        
        for key in KEYS:
            ida.create_data(address, FF_BYTE, 0x10, BADNODE)
            ida.create_struct(address, 0x10, entry)
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Unknown Command Keys
    
    KEYS = [
        '_SharedData_0',
        '_SharedKey_0_A',
        '_SharedKey_0_B',
        '_SharedData_1',
        '_SharedKey_1_A',
        '_SharedKey_1_B',
        '_SharedData_E',
        '_SharedKey_E_A',
        '_SharedKey_E_B',
    ]    
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '80 99 6F BB C8 B4 EB A3', 0x10, SEARCH_DOWN)
    
    if address == BADADDR:
        del KEYS[:6]
        address = ida.find_binary(mirror.start_ea, mirror.end_ea, 'AD 2F 32 2F 42 56 C4 9D', 0x10, SEARCH_DOWN)
    
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror g_debug_challenge_key
    
    #print('address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x20)
    ida.create_data(address, FF_BYTE, 0x20, BADNODE)
    ida.set_name(address, '_g_debug_challenge_key', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    address += 0x20
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror jigkick_expansion
    
    KEYS = [
        '_jigkick_expansion_0',
        '_jigkick_expansion_1',
        '_jigkick_expansion_2',
        '_jigkick_expansion_3',
        '_jigkick_expansion_4',
        '_jigkick_expansion_5',
        '_jigkick_expansion_6',
        '_jigkick_expansion_7',
        '_jigkick_expansion_8',
        '_jigkick_expansion_9',
        '_jigkick_expansion_A',
        '_jigkick_expansion_B',
        '_jigkick_expansion_C',
    ]
    
    #print('address: 0x%X' % address)
    
    size = len(KEYS) * 0x10
    ida.del_items(address, 0, size)
    
    for key in KEYS:
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        address += 0x10
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Unknown Shared Keys  
    
    KEYS = [
        '_SharedKey_0',
        '_SharedKey_1',
        '_SharedKey_E',   
    ]    
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '55 55 55 00', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR:
        address += 0x4
        
        size = len(KEYS) * 0xE
        ida.del_items(address, 0, size)
        
        for count, key in enumerate(KEYS):
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            ida.create_data(address, FF_WORD, 0x2, BADNODE)
            ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
            
            address += 0xE
        
        ida.del_items(address, 0, size)
        
        for count, key in enumerate(KEYS):
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            ida.create_data(address, FF_WORD, 0x2, BADNODE)
            ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
            
            address += 0xE
        
        # --------------------------------------------------------------------------------------------------------
        # Mirror Shared Keys
        
        KEYS = [
            '_SharedKey_B',
            '_SharedKey_F',
        ]
        
        extra = len(KEYS) * 0x16
        ida.del_items(address, 0, extra)
        
        for count, key in enumerate(KEYS):
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            ida.create_data(address, FF_WORD, 0x2, BADNODE)
            ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0xE,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0x12, FF_DWORD, 0x4, BADNODE)
            
            address += 0x16
        
        ida.del_items(address, 0, size)
        
        for count, key in enumerate(KEYS):
            ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
            ida.create_data(address, FF_WORD, 0x2, BADNODE)
            ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
            ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
            
            address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror SERVICE_0x900_DATA
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('address: 0x%X' % address)
    
    if address != BADADDR:
        ida.del_items(address, 0, 0x10)
        ida.create_data(address, FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address, 0x10, entry)
        ida.set_name(address, '_SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    
    print('# Finding Additional Functions...')
    function_search(1, 'D7 61 DD')
    function_search(1, 'FF C3 31 17')
    function_search(1, 'FB C3 31 17')
    function_search(1, 'FF 61 DD 8E FA')
    function_search(1, 'FF 61 DD C7')
    function_search(0, '61 DD C7')
    function_search(1, 'D7 C7 C3 C1')
    function_search(1, 'D7 C7 16')
    function_search(1, 'D7 30 02 00 C1')
    function_search(1, 'D7 C7 C1')
    function_search(1, 'D7 C7 88')
    function_search(1, 'D7 C7 20')
    function_search(1, 'D7 C7 41')
    function_search(1, 'D7 C7 36')
    function_search(1, '00 C7 C3 C1 FB')
    function_search(1, 'FF C7 57')
    function_search(2, '00 00 C7 C5 C1')
    
    # --------------------------------------------------------------------------------------------------------
    
    print('# Done!')
    return 1

# PROGRAM END