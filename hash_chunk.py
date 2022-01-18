#!/usr/bin/python3

import os
import hashlib
import argparse
import math

g_args = None

def parse_args():
    parser = argparse.ArgumentParser(description = "hash chunk checker - by /robex/")
    parser.add_argument("-s", metavar = "size", type = auto_int, help = "chunk size (bytes), default 1 MiB")
    parser.add_argument("-o", metavar = "offset", type = auto_int, help = "where to start in the file (bytes)")
    parser.add_argument("-l", metavar = "length", type = auto_int, help = "how many bytes to check in total")
    parser.add_argument("-x", help = "show chunk boundaries in hexadecimal base", action = "store_true")
    parser.add_argument("file1", help = "first file to check")
    parser.add_argument("file2", help = "second file to check")

    args = parser.parse_args()
    return args

def auto_int(x):
    return int(x, 0)

def calc_hash(fname, start, size):
    hash_sha1 = hashlib.sha1()
    
    with open(fname, "rb") as f:
        f.seek(start)
        hc_size = 4096
        nchunks = math.ceil(size / hc_size)
        for i in range(nchunks):
            if (i + 1) * hc_size > size:
                hc_size = size - (i * hc_size)
            chunk = f.read(hc_size)
            hash_sha1.update(chunk)
            
    return hash_sha1.hexdigest().lower()

def get_format(n):
    if g_args.x:
        return "{:08x}".format(n) + "h"
    else:
        return "{:08d}".format(n)

def __main__():
    global g_args
    g_args = parse_args()

    # 1 MiB
    chunksize_bytes = 2 ** 20
    if g_args.s is not None:
        chunksize_bytes = g_args.s

    fsize = 0
    if os.path.isfile(g_args.file1) and os.path.isfile(g_args.file2):
        fsize1 = os.path.getsize(g_args.file1)
        fsize2 = os.path.getsize(g_args.file2)
        fsize = min(fsize1, fsize2)
    else:
        print("fatal: file not found")
        return

    length = fsize
    offset = 0
    rem_len = fsize

    if g_args.o is not None:
        rem_len = fsize - g_args.o
        length = rem_len
        offset = g_args.o
        if offset > fsize:
            print("fatal: offset must be smaller than file size")
            
    if g_args.l is not None:
        length = g_args.l
        if g_args.l > rem_len:
            print("fatal: total length must be smaller or equal than file size minus offset")
            return

    if chunksize_bytes > length:
        chunksize_bytes = length
    nchunks = math.ceil(length / chunksize_bytes)
    nmatched = 0
    
    for i in range(nchunks):
        bound_low = int(offset + i * chunksize_bytes)
        if bound_low + chunksize_bytes > fsize:
            chunksize_bytes = fsize - bound_low
        bound_high = int(bound_low + chunksize_bytes - 1)
        
        hash1 = calc_hash(g_args.file1, bound_low, chunksize_bytes)
        hash2 = calc_hash(g_args.file2, bound_low, chunksize_bytes)
        res = ""
        if hash1 == hash2:
            res = "MATCH"
            nmatched += 1
        else:
            res = "MISMATCH"
            
        print("[" + get_format(bound_low) + "-" + get_format(bound_high) + "]:\t"
            + hash1[0:6] + "...  "
            + hash2[0:6] + "...  "
            + res)
    
    nchecked = int(nchunks)
    print("\n## STATS ##")
    print("Chunks checked: " + str(nchecked))
    print("Chunks matching: " + str(nmatched))
    print("Chunks mismatching: " + str(nchecked - nmatched))

__main__()