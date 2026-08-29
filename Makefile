include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=luci-app-client-access
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=luci-app-client-access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

CLIENT_ACCESS_PACKAGE_SET?=full

ifneq ($(CLIENT_ACCESS_PACKAGE_SET),core-luci)
PKG_BUILD_DEPENDS:=HAS_BPF_TOOLCHAIN:bpf-headers
endif

include $(INCLUDE_DIR)/package.mk
ifneq ($(CLIENT_ACCESS_PACKAGE_SET),core-luci)
include $(INCLUDE_DIR)/bpf.mk
endif

define Package/luci-app-client-access
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI frontend for Client Access
  DEPENDS:=+client-access-core +luci-base +rpcd +rpcd-mod-ucode
endef

define Package/luci-app-client-access/description
 Web frontend for the headless Client Access control plane.
endef

define Package/client-access-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Headless identity-based LAN Internet access control
  DEPENDS:=+firewall4 +nftables-json +ucode +ucode-mod-fs +ucode-mod-ubus \
	+ucode-mod-uci +ucode-mod-uloop
endef

define Package/client-access-core/description
 Headless Client Access control plane and nftables datapath for OpenWrt and
 ImmortalWrt. LuCI and the TC eBPF backend are optional clients of this package.
endef

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

define Package/client-access-core/conffiles
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

define Package/client-access-core/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/root/etc/config/client_access $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/client-access $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface $(1)/etc/hotplug.d/ntp
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/hotplug.d/iface/90-client-access \
		$(1)/etc/hotplug.d/iface/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/hotplug.d/ntp/90-client-access \
		$(1)/etc/hotplug.d/ntp/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/root/usr/sbin/client-accessd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/usr/share/ucode/client_access
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/ucode/client_access/*.uc \
		$(1)/usr/share/ucode/client_access/
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/table-pre
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/nftables.d/table-pre/30-client-access.nft \
		$(1)/usr/share/nftables.d/table-pre/
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/forward
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/nftables.d/chain-pre/forward/30-client-access.nft \
		$(1)/usr/share/nftables.d/chain-pre/forward/
endef

define Package/luci-app-client-access/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/client-access
	$(CP) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/view/client-access/* \
		$(1)/www/luci-static/resources/view/client-access/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/client-access
	$(CP) $(PKG_BUILD_DIR)/htdocs/luci-static/resources/client-access/* \
		$(1)/www/luci-static/resources/client-access/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/luci/menu.d/luci-app-client-access.json \
		$(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/share/rpcd/acl.d/luci-app-client-access.json \
		$(1)/usr/share/rpcd/acl.d/
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

define Package/client-access-core/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/etc/init.d/client-access enable >/dev/null 2>&1 || true
	/etc/init.d/firewall reload >/dev/null 2>&1 || true
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

define Package/client-access-core/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/etc/init.d/client-access stop >/dev/null 2>&1 || true
}
exit 0
endef

define Package/luci-app-client-access/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
endef

define Package/luci-app-client-access/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,client-access-core))
$(eval $(call BuildPackage,luci-app-client-access))
ifneq ($(CLIENT_ACCESS_PACKAGE_SET),core-luci)
$(eval $(call BuildPackage,client-access-bpf))
endif
