"""
Sample from 010 editor
struct FILE {
    struct HEADER {
        char    type[4];
        int     version;
        int     numRecords;
    } header;

    struct RECORD {
        int     employeeId;
        char    name[40];
        float   salary;
    } record[ header.numRecords ];

} file;
"""

