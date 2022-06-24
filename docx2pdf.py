# Python3 program to convert docx to pdf
# using docx2pdf module

# Import the convert method from the
# docx2pdf module
from docx2pdf import convert

# Converting docx present in the same folder
# as the python file
convert("D:\\Workspace\\eregistry_bc_new")

# Converting docx specifying both the input
# and output paths
convert("D:\\Workspace\\eregistry_bc_new\\DCB_loan_booklet.docx", "D:\\Workspace\\eregistry_bc_new")

# Notice that the output filename need not be
# the same as the docx

# Bulk Conversion
#convert("GeeksForGeeks\")
def convert():
    return None