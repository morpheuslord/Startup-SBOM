# Startup-SBOM

This is a simple SBOM utility which aims to provide an insider view on which packages are getting executed.

The process and objective is simple we can get a clear perspective view on the packages installed by APT (*currently working on implementing this for RPM and other package managers*). This is mainly needed to check which all packages are actually being executed.

## Installation
The packages needed are mentioned in the  `requirements.txt` file and can be installed using pip:
```bash
pip3 install -r requirements.txt
```

## Usage
- First of all install the packages.
- Secondly , you need to set up environment variables such as:
    - `Mount the image:` Currently I am still working on a mechanism to automatically define a mount point and mount different types of images and volumes but its still quite a task for me.
- Finally run the tool to list all the packages.


| Argument          | Description                                                                                                      |
|-------------------|------------------------------------------------------------------------------------------------------------------|
| `--analysis-mode` | Specifies the mode of operation. Default is `static`. Choices are `static` and `chroot`.                         |
| `--static-type`   | Specifies the type of analysis for static mode. Required for static mode only. Choices are `info` and `service`. |
| `--volume-path`   | Specifies the path to the mounted volume. Default is `/mnt`.                                                     |
| `--save-file`     | Specifies the output file for JSON output.                                                                       |
| `--info-graphic`  | Specifies whether to generate visual plots for CHROOT analysis. Default is `True`.                               |

- **Static Info Analysis:**
    - This command runs the program in static analysis mode, specifically using the Info Directory analysis method.
    - It analyzes the packages installed on the mounted volume located at `/mnt`.
    - It saves the output in a JSON file named `output.json`.
    - It generates visual plots for CHROOT analysis.

    ```bash
    python3 main.py --analysis-mode static --static-type info --volume-path /mnt --save-file output.json
    ```
- **Static Service Analysis**

   - This command runs the program in static analysis mode, specifically using the Service file analysis method.
   - It analyzes the packages installed on the mounted volume located at `/custom_mount`.
   - It saves the output in a JSON file named `output.json`.
   - It does not generate visual plots for CHROOT analysis.
    ```bash
    python3 main.py --analysis-mode static --static-type service --volume-path /custom_mount --save-file output.json --info-graphic False
    ```

- **Chroot analysis with or without Graphic output:**
   - This command runs the program in chroot analysis mode.
   - It analyzes the packages installed on the mounted volume located at `/mnt`.
   - It saves the output in a JSON file named `output.json`.
   - It generates visual plots for CHROOT analysis.
   - For graphical output keep `--info-graphic` as `True` else `False`
    ```bash
    python3 main.py --analysis-mode chroot --volume-path /mnt --save-file output.json --info-graphic True/False
    ```

## Supporting Images
Currently the tool works on Debian based images I am working on incorporating support for other flavors of linux but the issue is the amount of research on the package managers.

I have to still look into ways if incorporating RPM which is the backend for dnf or yum and also work on packman to add support for arch and red-hat distros.

## Working
For the workings and process related documentation please read the wiki page: [Link](https://github.com/morpheuslord/Startup-SBOM/wiki)
