import argparse
import os
from analyzers.apt.static_analyzer import apt_static_analysis
from analyzers.apt.chroot_analyzer import apt_chroot_analysis
from analyzers.rpm.rpm_chroot_analyzer import rpm_chroot_analysis
from analyzers.rpm.rpm_static_analyzer import rpm_static_analysis


class main():
    def __init__(self):
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
        args = parser.parse_args()
        mode = args.analysis_mode
        volume_path = args.volume_path
        static_type = args.static_type
        output_opt = args.save_file
        info_graphic = args.info_graphic
        package_mgr = ""
        if os.path.exists(f"{volume_path}/var/lib/dpkg"):
            package_mgr = "apt"
        elif os.path.exists(f"{volume_path}/var/lib/rpm"):
            package_mgr = "rpm"
        else:
            print("Image not supported")
            quit()

        print(package_mgr)

        if package_mgr == "apt":
            if mode == 'static':
                if static_type == "":
                    static_type = "info"
                apt_static_analysis(volume_path, static_type, output_opt)
            elif mode == 'chroot':
                apt_chroot_analysis(volume_path, output_opt,
                                    graphic_plot=info_graphic)
        elif package_mgr == "rpm":
            if mode == 'static':
                if static_type == "":
                    static_type = "info"
                rpm_static_analysis(volume_path, static_type, output_opt)
            elif mode == 'chroot':
                rpm_chroot_analysis(volume_path, output_opt,
                                    graphic_plot=info_graphic)
            rpm_chroot_analysis(volume_path, output_opt)
        else:
            print("Image not supported")


if __name__ == "__main__":
    main()
