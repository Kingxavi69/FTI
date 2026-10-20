# File Type Identifier

A small, dependency-free Python command-line tool that recognizes common file
types from their content and reports known mismatches between a file signature
and its filename extension. It runs on Kali Linux and other systems with Python
3.10 or newer.

## Run

```bash
python3 filetype_id.py /path/to/file
```

Check multiple files, scan a directory recursively, or produce JSON:

```bash
python3 filetype_id.py file1 file2
python3 filetype_id.py --recursive /path/to/directory
python3 filetype_id.py --json /path/to/file
```

Use `--check` in scripts to return status `1` when a recognized file type has a
known extension mismatch. The tool returns status `2` if it cannot read a path
or a directory was supplied without `--recursive`; otherwise it returns `0`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Safety and limitations

The tool reads only a small header from each file and does not execute, extract,
or modify files. It recognizes common image, document, archive, audio, and
executable signatures. Unknown data remains unknown; some formats share
containers or have variable layouts, so a signature result is an identification
hint rather than a complete format validation. An extension mismatch is
suspicious, not proof of malware, and a matching extension does not mean a file
is safe. This is not an antivirus scanner.
