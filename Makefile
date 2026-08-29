include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=luci-app-client-access
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=luci-app-client-access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=HAS_BPF_TOOLCHAIN:bpf-headers

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk

define Package/luci-app-client-access
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Identity and application-aware LAN Internet access control
  DEPENDS:=+luci-base +firewall4 +nftables-json +rpcd +rpcd-mod-ucode \
	+ucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-uloop
endef

define Package/luci-app-client-access/description
 Identity-based OpenWrt and ImmortalWrt Internet access control with an
 independent bounded TC eBPF application-policy workflow.
endef

define Package/client-access-bpf
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TC eBPF application-filter backend for Client Access
  DEPENDS:=+luci-app-client-access +libbpf +kmod-sched-bpf $(BPF_DEPENDS)
endef

define Package/client-access-bpf/description
 Optional bounded application-classification and enforcement layer for Client
 Access. The nftables-only controller remains usable without this package.
endef

define Package/luci-app-client-access/conffiles
/etc/config/client_access
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./htdocs ./root ./src $(PKG_BUILD_DIR)/
endef

ifneq ($(CONFIG_PACKAGE_client-access-bpf),)
define Build/Compile
	$(call CompileBPF,$(PKG_BUILD_DIR)/src/client-access-bpf.c)
	$(MAKE) -C $(PKG_BUILD_DIR)/src \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LDLIBS="-lbpf"
endef
else
define Build/Compile
endef
endif

define Package/luci-app-client-access/install
	$(INSTALL_DIR) $(1)/www
	$(CP) $(PKG_BUILD_DIR)/htdocs/* $(1)/www/
	$(INSTALL_DIR) $(1)/
	$(CP) $(PKG_BUILD_DIR)/root/* $(1)/
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
	/usr/sbin/client-access-bpfctl unload >/dev/null 2>&1 || exit 1
}
exit 0
endef

define Package/luci-app-client-access/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
	/etc/init.d/client-access enable >/dev/null 2>&1 || true
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,luci-app-client-access))
$(eval $(call BuildPackage,client-access-bpf))
