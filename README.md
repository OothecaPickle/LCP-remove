# LCP Removal Script

## Requirements

Before running the script, ensure you have the necessary dependencies installed. You can do so by running:

```bash
pip install pycryptodome
```

## Instructions

1. **Open the .lcpl file in Thorium Reader:**  
   Thorium is a free ebook reader that supports LCP-protected files. You can download it from the official website.

2. **Export the ebook as an .lcpa file:**  
   - In Thorium Reader, right-click on the book you want to decrypt.
   - Select the option to export it as an `.lcpa` file (LCP archive).

3. **Run the decryption script:**  
   Use the following command to decrypt the `.lcpa` file:
   
   ```bash
   python lcpremove.py -key <your_passphrase_key> <path_to_ebook_file>
   ```

   Replace `<your_passphrase_key>` with the passphrase you received when purchasing or borrowing the ebook, and `<path_to_ebook_file>` with the path to the `.lcpa` file.

4. **Access the decrypted files:**  
   Once the script runs successfully, all decrypted content will be saved in a new folder created in the same directory as the `.lcpa` file.

   - If the `.lcpa` file contains an image file (such as `.jpg`, `.jpeg`, or `.png`) for an audiobook, the image will automatically be copied to the output folder.

## Notes

- This script has been tested on both Windows and Linux.
- Although Thorium is used here as an example for exporting LCP-protected audiobooks and ebooks, any LCP-compatible software with export functionality can be used.
