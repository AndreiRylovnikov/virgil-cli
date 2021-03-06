/**
 * Copyright (C) 2015-2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <cli/formatter/CardFormatter.h>

#include <cli/types/EnumHelper.h>

using cli::formatter::CardFormatter;
using cli::model::Card;
using cli::model::CardProperty;


std::string CardFormatter::format(const Card& card) const {
    return doFormat(card);
}

void CardFormatter::showProperty(CardProperty cardProperty) {
    cli::types::addFlag(cardProperty, &settings_);
}

void CardFormatter::showProperty(std::initializer_list<CardProperty> cardProperties) {
    for (auto property : cardProperties) {
        showProperty(property);
    }
}

void CardFormatter::hideProperty(CardProperty cardProperty) {
    cli::types::removeFlag(cardProperty, &settings_);
}

void CardFormatter::hideProperty(std::initializer_list<CardProperty> cardProperties) {
    for (auto property : cardProperties) {
        hideProperty(property);
    }
}

bool CardFormatter::hasProperty(CardProperty cardProperty) const {
    return cli::types::hasFlag(cardProperty, settings_);
}

CardFormatter& CardFormatter::showBaseProperties() {
    showProperty({
            CardProperty::Identifier,
            CardProperty::Identity,
            CardProperty::IdentityType,
            CardProperty::Version,
            CardProperty::Scope,
            CardProperty::PublicKey
    });
    return *this;
}

CardFormatter& CardFormatter::showAllProperties() {
    showProperty({
            CardProperty::Identifier,
            CardProperty::Identity,
            CardProperty::IdentityType,
            CardProperty::Version,
            CardProperty::Scope,
            CardProperty::PublicKey,
            CardProperty::Data,
            CardProperty::Info,
            CardProperty::Signatures,
    });
    return *this;
}
