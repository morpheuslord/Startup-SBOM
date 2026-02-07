# Lazy imports to avoid loading RPM bindings on apt-based systems (and vice versa)
# Import specific analyzers only when needed

def apt_chroot_analysis(*args, **kwargs):
    from .apt_package_manager.chroot_analyzer import apt_chroot_analysis as _apt_chroot_analysis
    return _apt_chroot_analysis(*args, **kwargs)

def apt_static_analysis(*args, **kwargs):
    from .apt_package_manager.static_analyzer import apt_static_analysis as _apt_static_analysis
    return _apt_static_analysis(*args, **kwargs)

def rpm_chroot_analysis(*args, **kwargs):
    from .rpm_package_manager.rpm_chroot_analyzer import rpm_chroot_analysis as _rpm_chroot_analysis
    return _rpm_chroot_analysis(*args, **kwargs)

def rpm_static_analysis(*args, **kwargs):
    from .rpm_package_manager.rpm_static_analyzer import rpm_static_analysis as _rpm_static_analysis
    return _rpm_static_analysis(*args, **kwargs)


def pacman_chroot_analysis(*args, **kwargs):
    from .pacman_package_manager.pacman_chroot_analyzer import pacman_chroot_analysis as _pacman_chroot_analysis
    return _pacman_chroot_analysis(*args, **kwargs)


def pacman_static_analysis(*args, **kwargs):
    from .pacman_package_manager.pacman_static_analyzer import pacman_static_analysis as _pacman_static_analysis
    return _pacman_static_analysis(*args, **kwargs)
