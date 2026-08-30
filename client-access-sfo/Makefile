include $(TOPDIR)/rules.mk

PKG_NAME:=client-access-sfo
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Client Access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

CLIENT_ACCESS_REPO_DIR:=$(patsubst %/,%,$(dir $(realpath $(CURDIR))))

include $(INCLUDE_DIR)/package.mk

define Package/client-access-sfo
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Software flow-offload revocation backend for Client Access
  DEPENDS:=+client-access-core +client-access-bpf +libbpf \
	+libnetfilter-conntrack
endef

define Package/client-access-sfo/description
 Optional structured conntrack backend for canonical firewall4 software flow
 offload. It provides bounded targeted revocation without owning firewall
 flow-offload configuration or semantic policy.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/sfo/* $(PKG_BUILD_DIR)/
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/src/client-access-bpf.h $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib" \
		LDLIBS="-lbpf -lnetfilter_conntrack"
endef

define Package/client-access-sfo/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/client-access-sfoctl $(1)/usr/sbin/
endef

define Package/client-access-sfo/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

define Package/client-access-sfo/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	/usr/sbin/client-access-sfoctl baseline 2000 >/dev/null 2>&1 || exit 1
}
exit 0
endef

define Package/client-access-sfo/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}$${PKG_INSTROOT}" ] || {
	[ ! -x /etc/init.d/client-access ] || \
		/etc/init.d/client-access restart >/dev/null 2>&1 || true
}
exit 0
endef

$(eval $(call BuildPackage,client-access-sfo))
