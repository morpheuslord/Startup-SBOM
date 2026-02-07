import argparse
import os
from analyzers import apt_static_analysis
from analyzers import apt_chroot_analysis
from analyzers import rpm_chroot_analysis
from analyzers import rpm_static_analysis
from analyzers import pacman_chroot_analysis
from analyzers import pacman_static_analysis


class main():
    def __init__(self) -> None:
        parser = argparse.ArgumentParser(
            prog="main.py",
            description="""
                STARTUP SBOM:
                This is a automation to list out packages installed in
                linux systems and map them to the appropriate service files.
                The project is for analysis of packages installed and provide
                an insight into the inner workings of the system.
            """
        )
        parser.add_argument(
            '--analysis-mode',
            type=str,
            required=False,
            default='static',
            help="""
                This is required to mention the mode of operation the
                default mode is static and you can ether choose from static and
                chroot.
            """
        )
        parser.add_argument(
            '--static-type',
            type=str,
            required=False,
            default="info",
            help="""
            This is a necessary option for the static processing  mode only.
            It will make sure you are using ether the Service file analysis
            or the Info Directory analysis methods.
            """
        )
        parser.add_argument(
            '--volume-path',
            type=str,
            required=False,
            default='/mnt',
            help="""
                This the path to the mounted volume. The path is required and
                the default path is /mnt and you can change it to your own
                choice.
            """
        )
        parser.add_argument(
            "--save-file",
            type=str,
            required=False,
            default="",
            help="""
                Generates JSON output on what your are displayed and this can
                be used for future intigrations.
            """
        )
        parser.add_argument(
            "--info-graphic",
            type=bool,
            required=False,
            default=True,
            help="""
                Provides visual plots on the the different packages and
                associated Service Files and Target files which are being
                executed at boot. This is based on time of execution and
                is specific only to CHROOT analysis
            """
        )
        parser.add_argument(
            "--pkg-mgr",
            type=str,
            required=False,
            default="",
            help="""
                Provides visual plots on the the different packages and
                associated Service Files and Target files which are being
                executed at boot. This is based on time of execution and
                is specific only to CHROOT analysis
            """
        )
        parser.add_argument(
            "--cve-analysis",
            action='store_true',
            default=False,
            help="""
                Enable CVE vulnerability scanning for packages using the
                NIST NVD API. This will check each package for known
                vulnerabilities and display severity information.
                Note: This requires network access and may take time
                due to API rate limits.
            """
        )
        args = parser.parse_args()
        mode: str = args.analysis_mode
        volume_path: str = args.volume_path
        static_type: str = args.static_type
        output_opt: str = args.save_file
        info_graphic: bool = args.info_graphic
        package_mgr: str = args.pkg_mgr
        cve_analysis: bool = args.cve_analysis
        if package_mgr == "":
            if os.path.exists(f"{volume_path}/var/lib/dpkg"):
                package_mgr = "apt"
            elif os.path.exists(f"{volume_path}/var/lib/rpm"):
                package_mgr = "rpm"
            elif os.path.exists(f"{volume_path}/var/lib/pacman"):
                package_mgr = "pacman"
            else:
                print("Image not supported")
                quit()

        if package_mgr == "apt":
            if mode == 'static':
                apt_static_analysis(volume_path, static_type, output_opt, cve_analysis)
            elif mode == 'chroot':
                apt_chroot_analysis(
                    volume_path,
                    output_opt,
                    graphic_plot=info_graphic,
                    cve_analysis=cve_analysis
                )
        elif package_mgr == "rpm":
            if mode == 'static':
                rpm_static_analysis(volume_path, output_opt)
            elif mode == 'chroot':
                rpm_chroot_analysis(volume_path, output_opt,
                                    graphic_plot=info_graphic)
        elif package_mgr == "pacman":
            if mode == 'static':
                pacman_static_analysis(volume_path, static_type, output_opt, cve_analysis)
            elif mode == 'chroot':
                pacman_chroot_analysis(
                    volume_path,
                    output_opt,
                    graphic_plot=info_graphic,
                    cve_analysis=cve_analysis
                )
        else:
            print("Image not supported")


if __name__ == "__main__":
    main()
