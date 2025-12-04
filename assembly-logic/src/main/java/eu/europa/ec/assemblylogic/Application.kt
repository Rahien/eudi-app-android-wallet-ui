/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.assemblylogic

import android.app.Application
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import eu.europa.ec.analyticslogic.controller.AnalyticsController
import eu.europa.ec.assemblylogic.di.setupKoin
import eu.europa.ec.businesslogic.config.ConfigLogic
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.corelogic.worker.RevocationWorkManager
import eu.europa.ec.eudi.iso18013.transfer.readerauth.profile.*
import eu.europa.ec.eudi.rqesui.infrastructure.EudiRQESUi
import org.koin.android.ext.android.inject
import org.koin.core.KoinApplication
import java.lang.reflect.Field
import eu.europa.ec.eudi.iso18013.transfer.readerauth.profile.ProfileValidation
import eu.europa.ec.eudi.iso18013.transfer.readerauth.profile.ProfileValidationImpl
import java.security.cert.X509Certificate
import java.lang.reflect.Modifier


class Application : Application() {

    private val analyticsController: AnalyticsController by inject()
    private val configLogic: ConfigLogic by inject()
    private val walletCoreConfig: WalletCoreConfig by inject()

    override fun onCreate() {
        super.onCreate()
        overrideDefaultProfileValidation()
        initializeKoin().initializeRqes()
        initializeReporting()
        initializeRevocationWorkManager()
    }

    private fun KoinApplication.initializeRqes() {
        EudiRQESUi.setup(
            application = this@Application,
            config = configLogic.rqesConfig,
            koinApplication = this@initializeRqes
        )
    }

    private fun initializeKoin(): KoinApplication {
        return setupKoin()
    }

    private fun initializeReporting() {
        analyticsController.initialize(this)
    }

    private fun initializeRevocationWorkManager() {

        val periodicWorkRequest = PeriodicWorkRequest.Builder(
            workerClass = RevocationWorkManager::class.java,
            repeatInterval = walletCoreConfig.revocationInterval,
        ).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            RevocationWorkManager.REVOCATION_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            periodicWorkRequest
        )
    }

//    default validator requires READER_AUTH_OID = "1.0.18013.5.1.6" which we can't provide in our letsencrypt certificate csr and which is NOT NECESSARY ACCORDING TO THE SPEC
    fun overrideDefaultProfileValidation() {
        val clazz = ProfileValidation.Companion::class.java

        println("=== Static fields in ${clazz.name} ===")

        clazz.declaredFields.forEach { field ->
            val isStatic = Modifier.isStatic(field.modifiers)
            if (!isStatic) return@forEach

            field.isAccessible = true

            val typeName = field.type.name
            val modifiers = Modifier.toString(field.modifiers)
            val name = field.name

            val value = try {
                field.get(null)
            } catch (e: Throwable) {
                "<unreadable: ${e.message}>"
            }

            println("Field:")
            println("  name      = $name")
            println("  type      = $typeName")
            println("  modifiers = $modifiers")
            println("  value     = $value")
            println()
        }

        println("=== End of static field list ===")
        // Java class representing the companion object
        val companionClass = ProfileValidation.Companion::class.java

        // Find all static fields that match the type ProfileValidation
        val targetField: Field? = companionClass.declaredFields.firstOrNull { field ->
            Modifier.isStatic(field.modifiers) && field.name.equals("DEFAULT")
        }

        requireNotNull(targetField) { "Could not find static ProfileValidation field to override" }

        targetField.isAccessible = true



        // Set the new value
        targetField.set(null, ProfileValidationImpl(
            listOf(
                AuthorityKey(),
                CommonName(),
                CriticalExtensions(),
                KeyUsage(),
                MandatoryExtensions(),
                Period(),
                SignatureAlgorithm(),
                SubjectKey(),
            ),
        ))
    }
}