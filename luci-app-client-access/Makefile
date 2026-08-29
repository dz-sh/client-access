include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-client-access
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=luci-app-client-access contributors
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

CLIENT_ACCESS_REPO_DIR:=$(patsubst %/,%,$(dir $(realpath $(CURDIR))))

include $(INCLUDE_DIR)/package.mk

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

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/htdocs $(PKG_BUILD_DIR)/
	$(CP) $(CLIENT_ACCESS_REPO_DIR)/root $(PKG_BUILD_DIR)/
endef

define Build/Compile
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

$(eval $(call BuildPackage,luci-app-client-access))
