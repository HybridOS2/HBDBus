/**
 * @file config.h
 * @author Vincent Wei (https://github.com/VincentWei)
 * @date 2023/09/10
 * @brief The configuration header file of HBDBus.
 *
 * Copyright (C) 2023 FMSoft <https://www.fmsoft.cn>
 *
 * HBDBus is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * HBDBus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */

#if defined(HAVE_CONFIG_H) && HAVE_CONFIG_H && defined(BUILDING_WITH_CMAKE)
#include "cmakeconfig.h"
#endif

#include <wtf/Platform.h>
#include <wtf/ExportMacros.h>

#if !defined(HBDBUS_EXPORT)

#if defined(BUILDING_PURC) || defined(STATICALLY_LINKED_WITH_PURC)
#define HBDBUS_EXPORT WTF_EXPORT_DECLARATION
#else
#define HBDBUS_EXPORT WTF_IMPORT_DECLARATION
#endif

#endif
