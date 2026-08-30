include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=client-access-bpf
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Client Access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=HAS_BPF_TOOLCHAIN:bpf-headers

CLIENT_ACCESS_REPO_DIR:=$(patsubst %/,%,$(dir $(realpath $(CURDIR))))

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/client-access-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TC eBPF application-filter backend for Client Access
  DEPENDS:=+client-access-core +libbpf +kmod-sched-bpf $(BPF_DEPENDS)
endef

define Package/client-access-bpf/description
 Optional bounded application-classification and enforcement layer for Client
 Access. The nftables-only controller remains usable without this package.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/src $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/src/client-access-bpf.c)
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LDLIBS="-lbpf"
endef

define Package/client-access-bpf/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/client-access-bpfctl $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/lib/bpf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/client-access-bpf.o \
		$(1)/usr/lib/bpf/client-access-bpf.o
endef

define Package/client-access-bpf/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/usr/sbin/client-access-bpfctl load /usr/lib/bpf/client-access-bpf.o \
		>/dev/null 2>&1 || true
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

define Package/client-access-bpf/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/usr/sbin/client-access-bpfctl disable >/dev/null 2>&1 || true
	/usr/sbin/client-access-bpfctl unload >/dev/null 2>&1 || true
}
exit 0
endef

define Package/client-access-bpf/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	[ ! -x /etc/init.d/client-access ] || \
		/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,client-access-bpf))
